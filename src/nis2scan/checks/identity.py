"""Identity provider: MFA (Art. 21(2)(j)) and access control (Art. 21(2)(i))."""

import re
from datetime import datetime

from nis2scan.config import Profile
from nis2scan.registry import check, failed, passed

ACCESS = ["REQ-NIS2-21.2.I"]


@check(
    id="CHK-IDP-001",
    title="Every staff account has MFA enrolled or is forced to enrol",
    requirements=[
        "REQ-NIS2-21.2.J",
        "REQ-CIR2690-11.7.1-01",  # MFA for users
        "REQ-CIR2690-11.3.2-01",  # strong authentication for admin accounts
    ],
    coverage="partial",
    severity="high",
    severity_rationale="Staff accounts reach customer systems; a stolen password alone must not be enough.",
    target_type="identity_provider",
    collector="keycloak_realm",
)
def mfa_enforced(ev: dict, profile: Profile, now: datetime):
    totp = next((a for a in ev["required_actions"] if a["alias"] == "CONFIGURE_TOTP"), None)
    new_users_forced = bool(totp and totp["enabled"] and totp["defaultAction"])
    without_mfa = [
        u["username"]
        for u in ev["users"]
        if u["enabled"]
        and "otp" not in u["credential_types"]
        and "CONFIGURE_TOTP" not in u["required_actions"]
    ]
    observed = {"new_users_must_enrol_otp": new_users_forced, "users_without_mfa": without_mfa}
    expected = {"new_users_must_enrol_otp": True, "users_without_mfa": []}
    problems = []
    if without_mfa:
        problems.append(f"{len(without_mfa)} account(s) without MFA: {', '.join(without_mfa)}")
    if not new_users_forced:
        problems.append("new accounts are not required to enrol OTP")
    if problems:
        return failed("; ".join(problems), observed, expected)
    return passed(f"All {len(ev['users'])} accounts have or must enrol OTP", observed, expected)


@check(
    id="CHK-IDP-002",
    title="Brute-force protection is enabled on the staff realm",
    requirements=[
        *ACCESS,
        "REQ-CIR2690-11.6.2-04",  # blocking after failed log-ins
    ],
    coverage="partial",
    severity="medium",
    severity_rationale="Limits online password guessing against staff accounts.",
    target_type="identity_provider",
    collector="keycloak_realm",
)
def brute_force_protection(ev: dict, profile: Profile, now: datetime):
    enabled = bool(ev["settings"]["bruteForceProtected"])
    observed = {
        "bruteForceProtected": enabled,
        "failureFactor": ev["settings"]["failureFactor"],
    }
    if not enabled:
        return failed("Brute-force protection is off", observed, {"bruteForceProtected": True})
    return passed("Brute-force protection is on", observed, {"bruteForceProtected": True})


def min_password_length(policy: str | None) -> int:
    """Extract N from a Keycloak policy string like 'length(12) and notUsername'."""
    match = re.search(r"\blength\((\d+)\)", policy or "")
    return int(match.group(1)) if match else 0


@check(
    id="CHK-IDP-003",
    title="Password policy enforces the profile's minimum length",
    requirements=[
        *ACCESS,
        "REQ-CIR2690-11.6.2-01",  # strength of authentication
        "REQ-CIR2690-11.7.2-01",  # strength of authentication
    ],
    coverage="partial",
    severity="medium",
    severity_rationale="Short passwords weaken the first factor even when MFA is in place.",
    target_type="identity_provider",
    collector="keycloak_realm",
)
def password_length(ev: dict, profile: Profile, now: datetime):
    policy = ev["settings"]["passwordPolicy"]
    length = min_password_length(policy)
    required = profile.identity.min_password_length
    observed = {"passwordPolicy": policy, "min_length": length}
    expected = {"min_length_at_least": required}
    if length < required:
        what = f"minimum length is {length}" if length else "no minimum length is set"
        return failed(f"Password policy: {what}", observed, expected)
    return passed(f"Password policy requires {length} characters", observed, expected)


@check(
    id="CHK-IDP-004",
    title="Default admin credentials are rejected",
    requirements=[
        *ACCESS,
        "REQ-CIR2690-11.6.2-03",  # credentials changed initially
    ],
    coverage="partial",
    severity="critical",
    severity_rationale="Default admin credentials give anyone full control of every staff identity.",
    target_type="identity_provider",
    collector="keycloak_default_admin",
)
def no_default_admin(ev: dict, profile: Profile, now: datetime):
    observed = {"username_tried": ev["username_tried"], "http_status": ev["http_status"]}
    if ev["accepted"]:
        return failed("Admin console accepts admin/admin", observed, {"accepted": False})
    return passed("Default admin credentials are rejected", observed, {"accepted": False})
