"""Keycloak: realm security settings and users' second factors, via the admin REST API."""

from __future__ import annotations

import re
from typing import Any

from nis2scan.adapters._http import HttpError, get_json, request
from nis2scan.adapters.identity import (
    DefaultLoginResult,
    IdentityAdapter,
    IdentityEvidence,
    IdentityUser,
    adapter,
)
from nis2scan.config import IdpTarget
from nis2scan.registry import CollectorError

DEFAULT_ADMIN = ("admin", "admin")
SECOND_FACTORS = {"otp", "webauthn", "webauthn-passwordless"}
ENROL_ACTIONS = {"CONFIGURE_TOTP", "webauthn-register", "webauthn-register-passwordless"}


def _token(base_url: str, username: str, password: str) -> tuple[int, str | None]:
    """Log in to the master realm with the admin CLI client; (HTTP status, token or None)."""
    url = f"{base_url}/realms/master/protocol/openid-connect/token"
    form = {"grant_type": "password", "client_id": "admin-cli"}
    try:
        body, _ = request(url, data=form | {"username": username, "password": password})
    except HttpError as exc:
        return exc.status, None
    return 200, body["access_token"]


def min_password_length(policy: str | None) -> int:
    """Extract N from a Keycloak policy string like 'length(12) and notUsername'."""
    match = re.search(r"\blength\((\d+)\)", policy or "")
    return int(match.group(1)) if match else 0


@adapter
class Keycloak(IdentityAdapter):
    product = "keycloak"
    label = "Keycloak"
    needs = ("realm", "admin_user", "admin_password_env")
    access = (
        "A Keycloak admin account for the realm with the realm-management roles "
        "view-realm and view-users"
    )

    def check_access(self, idp: IdpTarget, secret) -> None:
        status, token = _token(idp.url.rstrip("/"), idp.admin_user, secret(idp.admin_password_env))
        if not token:
            raise CollectorError(f"admin login failed with HTTP {status}")

    def fetch(self, idp: IdpTarget, secret) -> dict[str, Any]:
        base = idp.url.rstrip("/")
        status, token = _token(base, idp.admin_user, secret(idp.admin_password_env))
        if not token:
            raise CollectorError(f"admin login to {base} failed with HTTP {status}")
        headers = {"Authorization": f"Bearer {token}"}

        def get(path: str):
            return get_json(f"{base}/admin/realms/{path}", headers)

        realm = get(idp.realm)
        actions = get(f"{idp.realm}/authentication/required-actions")
        users = []
        for user in get(f"{idp.realm}/users?max=1000"):
            creds = get(f"{idp.realm}/users/{user['id']}/credentials")
            users.append(
                {
                    "username": user["username"],
                    "enabled": user["enabled"],
                    "required_actions": user.get("requiredActions", []),
                    "credential_types": sorted({c["type"] for c in creds}),
                }
            )
        return {
            "realm": idp.realm,
            "settings": {
                key: realm.get(key)
                for key in (
                    "bruteForceProtected",
                    "failureFactor",
                    "passwordPolicy",
                    "otpPolicyType",
                )
            },
            "required_actions": [
                {k: a[k] for k in ("alias", "enabled", "defaultAction")} for a in actions
            ],
            "users": users,
        }

    def normalize(self, raw: dict[str, Any]) -> IdentityEvidence:
        settings = raw["settings"]
        enrol_by_default = any(
            a["alias"] in ENROL_ACTIONS and a["enabled"] and a["defaultAction"]
            for a in raw["required_actions"]
        )
        lockout = bool(settings["bruteForceProtected"])
        return IdentityEvidence(
            tenant=raw["realm"],
            users=[
                IdentityUser(
                    username=u["username"],
                    enabled=u["enabled"],
                    mfa_enrolled=bool(SECOND_FACTORS & set(u["credential_types"])),
                    mfa_pending=bool(ENROL_ACTIONS & set(u["required_actions"])),
                )
                for u in raw["users"]
            ],
            new_users_must_enrol_mfa=enrol_by_default,
            lockout_enabled=lockout,
            lockout_max_attempts=settings["failureFactor"] if lockout else None,
            password_min_length=min_password_length(settings["passwordPolicy"]),
            password_policy=settings["passwordPolicy"] or "no password policy",
        )

    def try_default_login(self, idp: IdpTarget) -> DefaultLoginResult:
        """One attempt with the documented default admin/admin; one try cannot lock the account."""
        status, token = _token(idp.url.rstrip("/"), *DEFAULT_ADMIN)
        return DefaultLoginResult(
            username_tried=DEFAULT_ADMIN[0], accepted=token is not None, detail=f"HTTP {status}"
        )
