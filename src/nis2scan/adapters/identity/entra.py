"""Microsoft Entra ID: users' authentication methods, and where MFA is enforced.

Uses Microsoft Graph v1.0 with an app registration (client credentials) holding the
application permissions User.Read.All, UserAuthenticationMethod.Read.All,
Policy.Read.All and Directory.Read.All. Only GET requests are made. Reads
/organization, /users, /users/{id}/authentication/methods,
/policies/identitySecurityDefaultsEnforcementPolicy,
/identity/conditionalAccess/policies and /groupSettings.

Where MFA is enforced: either security defaults (a tenant-wide baseline, on by
default in new tenants) or Conditional Access policies (Entra ID P1 and above).
Without P1, Graph refuses to list Conditional Access policies; that is recorded as
"not available", not as an error. A Conditional Access policy counts only if it is
enabled (not report-only), covers all users and all cloud apps, and requires MFA or
an authentication strength. Users or groups it excludes can sign in without it and
are reported as such.

Security defaults are read as enforcing MFA. They make every user register MFA and
always require it for administrators, but ask other users for it "when necessary"
(Microsoft decides, based on sign-in risk). This follows Microsoft's own position that
security defaults are the MFA baseline for tenants without Conditional Access, and the
evidence records which mechanism applied, so a reviewer can judge it.

Password rules for cloud accounts are fixed by Microsoft: 8 to 256 characters. Smart
lockout is always on; its threshold is 10 failed attempts unless the tenant set its
own in the "Password Rule Settings" directory setting (which needs P1). Accounts
synchronised from an on-premises Active Directory follow that directory's policy
instead, which this adapter does not read.

As with Okta, a user without a registered second factor counts as without MFA even
if a policy will make them register at their next sign-in.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from nis2scan.adapters._http import HttpError, get_json, get_odata, request
from nis2scan.adapters.identity import IdentityAdapter, IdentityEvidence, IdentityUser, adapter
from nis2scan.config import IdpTarget
from nis2scan.registry import CollectorError

GRAPH = "https://graph.microsoft.com/v1.0"
# Methods that are not a second factor: knowledge- or inbox-based, or one-time bootstrap.
NOT_SECOND_FACTORS = {"password", "email", "temporaryAccessPass"}
CLOUD_MIN_PASSWORD_LENGTH = 8  # fixed by Microsoft for cloud-only accounts
DEFAULT_LOCKOUT_THRESHOLD = 10  # smart lockout default
SIGN_IN = "Microsoft Entra ID sign-in"


def tenant_of(idp: IdpTarget) -> str:
    """The tenant ID or domain: the first path segment of the login URL."""
    tenant = urlparse(idp.url).path.strip("/").split("/")[0]
    if not tenant:
        raise CollectorError(
            "the Entra ID url must include the tenant, e.g. "
            "https://login.microsoftonline.com/<tenant-id>"
        )
    return tenant


def method_type(method: dict) -> str:
    """'#microsoft.graph.fido2AuthenticationMethod' -> 'fido2'."""
    name = method.get("@odata.type", "").rsplit(".", 1)[-1]
    return name.removesuffix("AuthenticationMethod")


def _token(idp: IdpTarget, secret) -> str:
    body, _ = request(
        f"https://login.microsoftonline.com/{tenant_of(idp)}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": idp.client_id,
            "client_secret": secret(idp.client_secret_env),
            "scope": "https://graph.microsoft.com/.default",
        },
    )
    return body["access_token"]


def enforces_mfa_for_everyone(policy: dict) -> bool:
    """An enabled Conditional Access policy requiring MFA for all users and all cloud apps."""
    conditions = policy.get("conditions") or {}
    users = conditions.get("users") or {}
    apps = conditions.get("applications") or {}
    grant = policy.get("grantControls") or {}
    return (
        policy.get("state") == "enabled"
        and "All" in (users.get("includeUsers") or [])
        and "All" in (apps.get("includeApplications") or [])
        and (
            "mfa" in (grant.get("builtInControls") or [])
            or bool(grant.get("authenticationStrength"))
        )
    )


def _exclusions(policy: dict) -> int:
    users = (policy.get("conditions") or {}).get("users") or {}
    return sum(len(users.get(k) or []) for k in ("excludeUsers", "excludeGroups", "excludeRoles"))


def password_only_sign_in(raw: dict) -> list[str]:
    if raw["security_defaults_enabled"]:
        return []
    policies = raw["conditional_access_policies"]
    enforcing = [p for p in policies or [] if enforces_mfa_for_everyone(p)]
    if not enforcing:
        reason = (
            "Conditional Access is not available in this tenant"
            if policies is None
            else "no enabled Conditional Access policy requires MFA for all users and apps"
        )
        return [f"{SIGN_IN} (security defaults are off and {reason})"]
    # One enforcing policy without exclusions covers everyone.
    if any(_exclusions(p) == 0 for p in enforcing):
        return []
    return [
        f"{SIGN_IN} for the {_exclusions(p)} users, groups or roles excluded from "
        f"Conditional Access policy '{p.get('displayName')}'"
        for p in enforcing
    ]


@adapter
class EntraId(IdentityAdapter):
    product = "entra-id"
    label = "Microsoft Entra ID"
    needs = ("client_id", "client_secret_env")
    access = (
        "A Microsoft Entra app registration with a client secret and the Microsoft Graph "
        "application permissions User.Read.All, UserAuthenticationMethod.Read.All, "
        "Policy.Read.All and Directory.Read.All, with admin consent granted"
    )

    def check_access(self, idp: IdpTarget, secret) -> None:
        get_json(
            f"{GRAPH}/organization?$select=id", {"Authorization": f"Bearer {_token(idp, secret)}"}
        )

    def fetch(self, idp: IdpTarget, secret) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {_token(idp, secret)}"}
        org = get_json(f"{GRAPH}/organization?$select=id,displayName", headers)["value"][0]
        users = []
        for user in get_odata(
            f"{GRAPH}/users?$select=id,userPrincipalName,accountEnabled,userType&$top=999", headers
        ):
            methods = get_odata(f"{GRAPH}/users/{user['id']}/authentication/methods", headers)
            users.append(
                {
                    "userPrincipalName": user["userPrincipalName"],
                    "accountEnabled": user["accountEnabled"],
                    "userType": user.get("userType"),
                    "methods": sorted(method_type(m) for m in methods),
                }
            )
        defaults = get_json(f"{GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy", headers)
        try:
            policies = get_odata(f"{GRAPH}/identity/conditionalAccess/policies", headers)
        except HttpError as exc:
            if exc.status != 403:
                raise
            policies = None  # the tenant has no Conditional Access licence
        settings = get_odata(f"{GRAPH}/groupSettings", headers)
        return {
            "tenant_id": org["id"],
            "tenant_name": org.get("displayName"),
            "users": users,
            "security_defaults_enabled": bool(defaults.get("isEnabled")),
            "conditional_access_policies": policies,
            "password_rule_settings": next(
                (
                    {v["name"]: v["value"] for v in s.get("values", [])}
                    for s in settings
                    if s.get("displayName") == "Password Rule Settings"
                ),
                None,
            ),
        }

    def normalize(self, raw: dict[str, Any]) -> IdentityEvidence:
        password_only = password_only_sign_in(raw)
        rules = raw.get("password_rule_settings") or {}
        threshold = int(rules.get("LockoutThreshold") or DEFAULT_LOCKOUT_THRESHOLD)
        return IdentityEvidence(
            tenant=raw.get("tenant_name") or raw["tenant_id"],
            users=[
                IdentityUser(
                    username=u["userPrincipalName"],
                    enabled=u["accountEnabled"],
                    mfa_enrolled=any(m not in NOT_SECOND_FACTORS for m in u["methods"]),
                )
                for u in raw["users"]
                if u.get("userType") != "Guest"  # guests authenticate in their home tenant
            ],
            new_users_must_enrol_mfa=raw["security_defaults_enabled"] or password_only == [],
            lockout_enabled=True,
            lockout_max_attempts=threshold,
            password_min_length=CLOUD_MIN_PASSWORD_LENGTH,
            password_policy=(
                f"Entra ID cloud accounts: {CLOUD_MIN_PASSWORD_LENGTH} to 256 characters, fixed "
                f"by Microsoft; smart lockout after {threshold} failed attempts"
            ),
            password_only_sign_in=password_only,
        )
