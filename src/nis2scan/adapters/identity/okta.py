"""Okta: users' factors and the password and authenticator-enrolment policies.

Uses the Okta Management API with an API token (`Authorization: SSWS <token>`):
GET /api/v1/users, /api/v1/users/{id}/factors, /api/v1/policies?type=PASSWORD and
/api/v1/policies?type=MFA_ENROLL. Only GET requests are made.

Two readings are deliberately conservative:
- A user without an active second factor counts as without MFA, even if an enrolment
  policy will prompt them at their next sign-in: until then their password alone
  signs them in, and whoever holds it could enrol a factor of their own.
- With several active policies, the weakest decides (shortest minimum length; lockout
  only if every policy has it), because the weakest policy applies to someone.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from nis2scan.adapters._http import get_json, get_paged
from nis2scan.adapters.identity import IdentityAdapter, IdentityEvidence, IdentityUser, adapter
from nis2scan.config import IdpTarget

# Knowledge- or inbox-based factors are not a second factor in the sense of MFA.
NOT_SECOND_FACTORS = {
    "password",
    "question",
    "email",
    "okta_password",
    "okta_email",
    "security_question",
}
DISABLED_STATUSES = {"STAGED", "SUSPENDED", "DEPROVISIONED"}
POLICY_FIELDS = ("id", "name", "status", "priority", "system", "settings")


def _policy(p: dict) -> dict:
    return {k: p.get(k) for k in POLICY_FIELDS}


def requires_second_factor(policy: dict) -> bool:
    """Whether an MFA_ENROLL policy requires enrolling a real second factor.

    Identity Engine orgs list `settings.authenticators`; Classic Engine orgs list
    `settings.factors`. Both give each one an `enroll.self` of REQUIRED, OPTIONAL
    or NOT_ALLOWED.
    """
    settings = policy.get("settings") or {}
    entries = [(a.get("key"), a.get("enroll") or {}) for a in settings.get("authenticators") or []]
    entries += [(k, v.get("enroll") or {}) for k, v in (settings.get("factors") or {}).items()]
    return any(
        key not in NOT_SECOND_FACTORS and enroll.get("self") == "REQUIRED"
        for key, enroll in entries
    )


@adapter
class Okta(IdentityAdapter):
    product = "okta"
    label = "Okta"
    needs = ("api_token_env",)
    access = (
        "An API token created by an administrator with the Read-only Administrator role "
        "(Security > API > Tokens), in the environment variable named by api_token_env."
    )

    def fetch(self, idp: IdpTarget, secret) -> dict[str, Any]:
        base = idp.url.rstrip("/")
        headers = {"Authorization": f"SSWS {secret(idp.api_token_env)}"}
        users = []
        for user in get_paged(f"{base}/api/v1/users?limit=200", headers):
            factors = get_json(f"{base}/api/v1/users/{user['id']}/factors", headers)
            users.append(
                {
                    "login": user["profile"]["login"],
                    "status": user["status"],
                    "factors": [
                        {k: f.get(k) for k in ("factorType", "provider", "status")} for f in factors
                    ],
                }
            )
        return {
            "org": urlparse(base).hostname,
            "users": users,
            "password_policies": [
                _policy(p) for p in get_json(f"{base}/api/v1/policies?type=PASSWORD", headers)
            ],
            "mfa_enroll_policies": [
                _policy(p) for p in get_json(f"{base}/api/v1/policies?type=MFA_ENROLL", headers)
            ],
        }

    def normalize(self, raw: dict[str, Any]) -> IdentityEvidence:
        password = [p for p in raw["password_policies"] if p["status"] == "ACTIVE"]
        enroll = [p for p in raw["mfa_enroll_policies"] if p["status"] == "ACTIVE"]

        def rules(p: dict) -> dict:
            return (p.get("settings") or {}).get("password") or {}

        lengths = [(rules(p).get("complexity") or {}).get("minLength") or 0 for p in password]
        attempts = [(rules(p).get("lockout") or {}).get("maxAttempts") or 0 for p in password]
        default_enroll = [p for p in enroll if p.get("system")] or enroll
        return IdentityEvidence(
            tenant=raw["org"],
            users=[
                IdentityUser(
                    username=u["login"],
                    enabled=u["status"] not in DISABLED_STATUSES,
                    mfa_enrolled=any(
                        f["status"] == "ACTIVE" and f["factorType"] not in NOT_SECOND_FACTORS
                        for f in u["factors"]
                    ),
                )
                for u in raw["users"]
            ],
            # The default enrolment policy is the one every user falls back to.
            new_users_must_enrol_mfa=bool(default_enroll)
            and all(requires_second_factor(p) for p in default_enroll),
            lockout_enabled=bool(attempts) and all(a > 0 for a in attempts),
            lockout_max_attempts=max(attempts) if attempts and all(attempts) else None,
            password_min_length=min(lengths) if lengths else 0,
            password_policy="; ".join(
                f"{p['name']}: minimum length {n}, lockout after {a or 'never'}"
                for p, n, a in zip(password, lengths, attempts, strict=True)
            )
            or "no active password policy",
        )
