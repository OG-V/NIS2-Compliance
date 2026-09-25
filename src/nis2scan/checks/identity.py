"""Identity provider: MFA (Art. 21(2)(j)) and access control (Art. 21(2)(i)).

These checks read the product-neutral IdentityEvidence, so they apply to every
identity provider with an adapter (see nis2scan.adapters.identity).
"""

from datetime import datetime

from nis2scan.adapters.identity import IdentityEvidence
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
    action="Turn on two-factor login for every account",
    effort="change",
    target_type="identity_provider",
    collector="idp_config",
)
def mfa_enforced(ev: dict, profile: Profile, now: datetime):
    idp = IdentityEvidence.model_validate(ev["identity"])
    without_mfa = idp.users_without_mfa
    observed = {
        "new_users_must_enrol_mfa": idp.new_users_must_enrol_mfa,
        "users_without_mfa": without_mfa,
    }
    expected = {"new_users_must_enrol_mfa": True, "users_without_mfa": []}
    if idp.external_accounts:  # their MFA is handled, and only visible, at their home provider
        observed["external_accounts"] = idp.external_accounts
    if idp.password_only_sign_in is not None:  # products with separate sign-in policies
        observed["password_only_sign_in"] = idp.password_only_sign_in
        expected["password_only_sign_in"] = []
    problems = []
    if without_mfa:
        problems.append(f"{len(without_mfa)} account(s) without MFA: {', '.join(without_mfa)}")
    if not idp.new_users_must_enrol_mfa:
        problems.append("new accounts are not required to enrol a second factor")
    if idp.password_only_sign_in:
        problems.append(f"a password alone signs in through {', '.join(idp.password_only_sign_in)}")
    if problems:
        message = "; ".join(problems)
        return failed(message[0].upper() + message[1:], observed, expected)
    external = len(idp.external_accounts)
    internal = len(idp.users) - external
    message = (
        f"All {internal} accounts have or must enrol MFA" if internal else "No internal accounts"
    )
    if external:
        message += f"; {external} external account(s) use their home provider's MFA"
    return passed(message, observed, expected)


@check(
    id="CHK-IDP-002",
    title="Accounts are locked after repeated failed logins",
    requirements=[
        *ACCESS,
        "REQ-CIR2690-11.6.2-04",  # blocking after failed log-ins
    ],
    coverage="partial",
    severity="medium",
    severity_rationale="Limits online password guessing against staff accounts.",
    action="Turn on protection against password guessing",
    effort="quick",
    target_type="identity_provider",
    collector="idp_config",
)
def brute_force_protection(ev: dict, profile: Profile, now: datetime):
    idp = IdentityEvidence.model_validate(ev["identity"])
    observed = {"lockout_enabled": idp.lockout_enabled, "max_attempts": idp.lockout_max_attempts}
    expected = {"lockout_enabled": True}
    if not idp.lockout_enabled:
        return failed("Accounts are never locked after failed logins", observed, expected)
    return passed(
        f"Accounts lock after {idp.lockout_max_attempts} failed logins", observed, expected
    )


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
    action="Set a minimum password length",
    effort="quick",
    target_type="identity_provider",
    collector="idp_config",
)
def password_length(ev: dict, profile: Profile, now: datetime):
    idp = IdentityEvidence.model_validate(ev["identity"])
    length = idp.password_min_length
    required = profile.identity.min_password_length
    observed = {"password_policy": idp.password_policy, "min_length": length}
    if idp.password_min_length_fixed:
        observed["min_length_fixed_by_vendor"] = True
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
    action="Change the default admin password",
    effort="quick",
    target_type="identity_provider",
    collector="idp_default_admin",
)
def no_default_admin(ev: dict, profile: Profile, now: datetime):
    observed = {"username_tried": ev["username_tried"], "result": ev["detail"]}
    if ev["accepted"]:
        return failed("Admin console accepts admin/admin", observed, {"accepted": False})
    return passed("Default admin credentials are rejected", observed, {"accepted": False})
