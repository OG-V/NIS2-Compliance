"""Plain-language "found / should be" lines for failing checks.

A finding's observed and expected values are precise but written for engineers
({"permitrootlogin": "yes"}). These formatters restate them for managers. They
are deterministic and use only the finding's own values, like the rest of the
report. Each one handles every failure branch of its check (see nis2scan/checks/).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import date, datetime

from nis2scan.checks.web import VERSION_ORDER


@dataclass(frozen=True)
class Plain:
    found: str
    should: str
    # Replaces the check's usual action and effort when this finding shows it cannot apply.
    action: str | None = None
    effort: str | None = None


def _list(items: list[str]) -> str:
    items = [str(i) for i in items]
    return items[0] if len(items) == 1 else f"{', '.join(items[:-1])} and {items[-1]}"


def _day(iso: str) -> str:
    d = datetime.fromisoformat(iso) if "T" in iso else date.fromisoformat(iso)
    return f"{d.day} {d:%B %Y}"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _assets(o: dict, e: dict) -> Plain:
    return Plain(
        f"Running but missing from the asset inventory: {_list(o['undeclared_services'])}.",
        "Every running service is listed in the asset inventory.",
    )


def _backup(o: dict, e: dict) -> Plain:
    should = f"A backup no older than {_plural(e['max_age_hours'], 'hour')}."
    if not o["snapshots"]:
        return Plain("There are no backups at all.", should)
    hours = o["age_hours"]
    age = _plural(int(hours // 24), "day") if hours >= 48 else _plural(int(hours), "hour")
    return Plain(f"The newest backup was taken on {_day(o['newest'])}, {age} ago.", should)


def _plan_content(o: dict, e: dict) -> Plain:
    return Plain(
        f"The incident plan does not cover: {_list(o['missing'])}.",
        f"The plan covers {_list(e['mentions'])}.",
    )


def _plan_review(o: dict, e: dict) -> Plain:
    should = f"The plan is reviewed at least every {_plural(e['max_review_age_days'], 'day')}."
    if "last_reviewed" not in o:
        return Plain("The incident plan does not record when it was last reviewed.", should)
    return Plain(
        f"The incident plan was last reviewed on {_day(o['last_reviewed'])}, "
        f"{_plural(o['age_days'], 'day')} ago.",
        should,
    )


def _mfa(o: dict, e: dict) -> Plain:
    problems = []
    if o["users_without_mfa"]:
        users = o["users_without_mfa"]
        problems.append(f"Accounts that log in with a password alone: {_list(users)}.")
    # Runs made before identity adapters existed call this field new_users_must_enrol_otp.
    if not o.get("new_users_must_enrol_mfa", o.get("new_users_must_enrol_otp")):
        problems.append("New accounts are not asked to set up two-factor login.")
    if o.get("password_only_sign_in"):
        problems.append(
            f"A password alone is enough to sign in through: {_list(o['password_only_sign_in'])}."
        )
    should = "Every account uses two-factor login, and new accounts must set it up."
    if "password_only_sign_in" in o:
        should += " No sign-in accepts a password alone."
    return Plain(" ".join(problems), should)


def _brute_force(o: dict, e: dict) -> Plain:
    return Plain(
        "Nothing stops someone from guessing passwords over and over.",
        "Accounts are locked for a while after repeated failed logins.",
    )


def _password_length(o: dict, e: dict) -> Plain:
    found = (
        f"Passwords can be as short as {_plural(o['min_length'], 'character')}."
        if o["min_length"]
        else "No minimum password length is set."
    )
    should = f"Passwords have at least {e['min_length_at_least']} characters."
    if o.get("min_length_fixed_by_vendor"):
        found += " The vendor fixes this minimum, so it cannot be raised."
        return Plain(
            found,
            should,
            action="Compensate for the fixed minimum: enforce MFA for every account, or move "
            "to passwordless sign-in, and record the decision as an accepted risk",
            effort="change",
        )
    return Plain(found, should)


def _default_admin(o: dict, e: dict) -> Plain:
    return Plain(
        f"The admin console accepted the default username “{o['username_tried']}” "
        "with its default password.",
        "The default login is refused.",
    )


def _log_retention(o: dict, e: dict) -> Plain:
    which = f"Logs in {o['scope']} are" if o.get("scope") else "Logs are"
    return Plain(
        f"{which} deleted after {_plural(o['retention_days'], 'day')}.",
        f"Logs are kept for at least {_plural(e['min_retention_days'], 'day')}.",
    )


def _ssh_methods(o: dict, e: dict) -> Plain:
    weak = [m for m in o["auth_methods_offered"] if m in e["not_offered"]]
    return Plain(
        f"The server accepts {_list(weak)} logins, which can be guessed or bypassed.",
        "Only key-based logins (public key) are accepted.",
    )


def _ssh_root(o: dict, e: dict) -> Plain:
    return Plain(
        f"Anyone with the root password can log straight in as administrator "
        f"(PermitRootLogin {o['permitrootlogin']}).",
        "Direct root login is switched off. Administrators log in as themselves first.",
    )


def _ssh_tries(o: dict, e: dict) -> Plain:
    return Plain(
        f"Each connection allows {_plural(o['maxauthtries'], 'login attempt')}.",
        f"At most {_plural(e['maxauthtries_at_most'], 'attempt')} per connection.",
    )


def _tls_versions(o: dict, e: dict) -> Plain:
    minimum = VERSION_ORDER.index(e["min_version"])
    old = [v for v in o["accepted_versions"] if VERSION_ORDER.index(v) < minimum]
    return Plain(
        f"The website still accepts {_list(old)}, which are outdated and can be attacked.",
        f"Only {e['min_version']} or newer is accepted.",
    )


def _certificate(o: dict, e: dict) -> Plain:
    days = o["days_left"]
    if days < 0:
        found = f"The website's certificate expired on {_day(o['not_after'])}."
    elif days < e["min_days_remaining"]:
        found = f"The website's certificate expires in {_plural(days, 'day')}."
    else:
        found = f"The website's certificate is not valid until {_day(o['not_before'])}."
    return Plain(found, f"A valid certificate with at least {e['min_days_remaining']} days left.")


def _https(o: dict, e: dict) -> Plain:
    location = o["location"] or ""
    redirects = 300 <= o["http_status"] < 400 and location.startswith("https://")
    problems = []
    if not redirects:
        problems.append("Visitors who type http:// stay on the unencrypted site")
    if not o["hsts"]:
        problems.append("browsers are not told to always use the encrypted site")
    found = "; ".join(problems)
    return Plain(
        found[0].upper() + found[1:] + ".",
        "Visitors on http:// are sent to https://, and browsers are told to always use it.",
    )


def _vulnerabilities(o: dict, e: dict) -> Plain:
    failing = o["failing"]
    total = sum(len(ids) for ids in failing.values())
    label = "/".join(s.lower() for s in e["severities"])
    parts = [f"{image} ({len(ids)})" for image, ids in failing.items()]
    found = (
        f"{_plural(total, f'known {label} flaw')} with an available fix, in "
        f"{_plural(len(failing), 'component')}: {_list(parts)}."
    )
    if o.get("os_end_of_support"):
        found += f" {_list(o['os_end_of_support'])} runs on an operating system that no longer gets updates."
    return Plain(
        found, f"No fixable {label} flaws, unless a documented risk exception covers them."
    )


FORMATTERS: dict[str, Callable[[dict, dict], Plain]] = {
    "CHK-AST-001": _assets,
    "CHK-BAK-001": _backup,
    "CHK-DOC-001": _plan_content,
    "CHK-DOC-002": _plan_review,
    "CHK-IDP-001": _mfa,
    "CHK-IDP-002": _brute_force,
    "CHK-IDP-003": _password_length,
    "CHK-IDP-004": _default_admin,
    "CHK-LOG-001": _log_retention,
    "CHK-SSH-001": _ssh_methods,
    "CHK-SSH-002": _ssh_root,
    "CHK-SSH-003": _ssh_tries,
    "CHK-TLS-001": _tls_versions,
    "CHK-TLS-002": _certificate,
    "CHK-TLS-003": _https,
    "CHK-VUL-001": _vulnerabilities,
}


def explain(check_id: str, observed: dict, expected: dict) -> Plain | None:
    """The plain-language lines for a failing finding, or None if there are none.

    None makes the report fall back to the check's own message, so a finding
    whose values do not have the expected shape still renders.
    """
    formatter = FORMATTERS.get(check_id)
    if formatter is None:
        return None
    try:
        return formatter(observed, expected)
    except (KeyError, TypeError, ValueError, IndexError):
        return None
