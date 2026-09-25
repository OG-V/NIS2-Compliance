"""Okta: users' factors, and the password, enrolment and sign-in policies.

Uses the Okta Management API with an API token (`Authorization: SSWS <token>`):
GET /api/v1/users, /api/v1/users/{id}/factors, and /api/v1/policies (with their
rules) of types PASSWORD, MFA_ENROLL, OKTA_SIGN_ON and ACCESS_POLICY. Only GET
requests are made.

Where MFA is enforced: Okta Identity Engine usually enforces it in authentication
policies (ACCESS_POLICY, one per app), whose rules require "2FA" or allow "1FA".
When a sign-in needs a factor the user lacks, Okta makes them enrol one, if the
enrolment policy allows it. So a new user must enrol MFA if the enrolment policy
requires it, or if no sign-in path accepts a password alone. The global session
policy (OKTA_SIGN_ON) can also require a factor for every sign-in; Classic Engine
orgs have only that one.

Rules with an Okta expression condition (e.g. the password-expiry recovery rule)
serve special flows and are not treated as sign-in paths. "2FA_If_Possible" is not
treated as password-only: Okta uses it on its account management policy so that
users without a factor can enrol one.

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

from nis2scan.adapters._http import HttpError, get_json, get_paged
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
RULE_FIELDS = ("name", "status", "priority", "conditions", "actions")


def _policy(p: dict) -> dict:
    return {k: p.get(k) for k in POLICY_FIELDS}


def _policies_with_rules(base: str, headers: dict, kind: str) -> list[dict] | None:
    """Policies of one type with their rules, or None if the org has no such type."""
    try:
        policies = get_json(f"{base}/api/v1/policies?type={kind}", headers)
    except HttpError as exc:
        if exc.status in (400, 404):  # e.g. ACCESS_POLICY on a Classic Engine org
            return None
        raise
    return [
        {
            **_policy(p),
            "rules": [
                {k: r.get(k) for k in RULE_FIELDS}
                for r in get_json(f"{base}/api/v1/policies/{p['id']}/rules", headers)
            ],
        }
        for p in policies
    ]


def _active_rules(policies: list[dict]) -> list[tuple[dict, dict]]:
    return [
        (p, r)
        for p in policies
        if p["status"] == "ACTIVE"
        for r in p.get("rules") or []
        if r["status"] == "ACTIVE"
    ]


def password_only_sign_in(raw: dict) -> list[str] | None:
    """Names of the sign-in policies that accept a password alone (see module docstring)."""
    if "sign_on_policies" not in raw:
        return None  # evidence from before sign-in policies were read
    session_rules = _active_rules(raw["sign_on_policies"])
    if session_rules and all(
        ((r.get("actions") or {}).get("signon") or {}).get("requireFactor")
        for _, r in session_rules
    ):
        return []  # every session needs a second factor, whatever the app
    if raw.get("access_policies") is None:  # Classic Engine: the session policy is all there is
        return sorted({p["name"] for p, _ in session_rules}) or ["no active sign-on rule"]
    return sorted(
        {
            p["name"]
            for p, r in _active_rules(raw["access_policies"])
            if not (r.get("conditions") or {}).get("elCondition")
            and ((r.get("actions") or {}).get("appSignOn") or {})
            .get("verificationMethod", {})
            .get("factorMode")
            == "1FA"
        }
    )


def _enrolment(policy: dict) -> list[tuple[str, str]]:
    settings = policy.get("settings") or {}
    entries = [(a.get("key"), a.get("enroll") or {}) for a in settings.get("authenticators") or []]
    entries += [(k, v.get("enroll") or {}) for k, v in (settings.get("factors") or {}).items()]
    return [(key, enroll.get("self")) for key, enroll in entries if key not in NOT_SECOND_FACTORS]


def allows_second_factor(policy: dict) -> bool:
    """Whether users may enrol a real second factor under an MFA_ENROLL policy."""
    return any(mode in ("REQUIRED", "OPTIONAL") for _, mode in _enrolment(policy))


def requires_second_factor(policy: dict) -> bool:
    """Whether an MFA_ENROLL policy requires enrolling a real second factor.

    Identity Engine orgs list `settings.authenticators`; Classic Engine orgs list
    `settings.factors`. Both give each one an `enroll.self` of REQUIRED, OPTIONAL
    or NOT_ALLOWED.
    """
    return any(mode == "REQUIRED" for _, mode in _enrolment(policy))


@adapter
class Okta(IdentityAdapter):
    product = "okta"
    label = "Okta"
    needs = ("api_token_env",)
    access = (
        "An Okta API token, created by a user with the Read-only Administrator role "
        "(Admin Console: Security > API > Tokens)"
    )

    def check_access(self, idp: IdpTarget, secret) -> None:
        headers = {"Authorization": f"SSWS {secret(idp.api_token_env)}"}
        get_json(f"{idp.url.rstrip('/')}/api/v1/users?limit=1", headers)

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
            "sign_on_policies": _policies_with_rules(base, headers, "OKTA_SIGN_ON") or [],
            "access_policies": _policies_with_rules(base, headers, "ACCESS_POLICY"),
        }

    def normalize(self, raw: dict[str, Any]) -> IdentityEvidence:
        password = [p for p in raw["password_policies"] if p["status"] == "ACTIVE"]
        enroll = [p for p in raw["mfa_enroll_policies"] if p["status"] == "ACTIVE"]

        def rules(p: dict) -> dict:
            return (p.get("settings") or {}).get("password") or {}

        lengths = [(rules(p).get("complexity") or {}).get("minLength") or 0 for p in password]
        attempts = [(rules(p).get("lockout") or {}).get("maxAttempts") or 0 for p in password]
        default_enroll = [p for p in enroll if p.get("system")] or enroll
        password_only = password_only_sign_in(raw)
        required_by_enrolment = bool(default_enroll) and all(
            requires_second_factor(p) for p in default_enroll
        )
        forced_at_sign_in = (
            password_only == []
            and bool(default_enroll)
            and all(allows_second_factor(p) for p in default_enroll)
        )
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
            new_users_must_enrol_mfa=required_by_enrolment or forced_at_sign_in,
            lockout_enabled=bool(attempts) and all(a > 0 for a in attempts),
            lockout_max_attempts=max(attempts) if attempts and all(attempts) else None,
            password_min_length=min(lengths) if lengths else 0,
            password_policy="; ".join(
                f"{p['name']}: minimum length {n}, lockout after {a or 'never'}"
                for p, n, a in zip(password, lengths, attempts, strict=True)
            )
            or "no active password policy",
            password_only_sign_in=password_only,
        )
