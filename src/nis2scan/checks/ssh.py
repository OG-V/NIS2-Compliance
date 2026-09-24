"""SSH access control (NIS2 Art. 21(2)(i))."""

from datetime import datetime

from nis2scan.config import Profile
from nis2scan.registry import check, failed, passed

ACCESS = ["REQ-NIS2-21.2.I"]


@check(
    id="CHK-SSH-001",
    title="SSH does not offer password authentication",
    requirements=ACCESS,
    coverage="partial",
    severity="high",
    severity_rationale="Password logins on an admin host can be brute-forced or phished.",
    target_type="ssh_host",
    collector="ssh_auth_methods",
)
def ssh_no_password_auth(ev: dict, profile: Profile, now: datetime):
    offered = ev["auth_methods_offered"]
    weak = [m for m in offered if m in ("password", "keyboard-interactive", "none")]
    observed = {"auth_methods_offered": offered}
    expected = {"not_offered": ["password", "keyboard-interactive", "none"]}
    if weak:
        return failed(f"Server offers {', '.join(weak)} authentication", observed, expected)
    return passed(f"Server offers only {', '.join(offered)}", observed, expected)


@check(
    id="CHK-SSH-002",
    title="Direct root login over SSH is disabled",
    requirements=ACCESS,
    coverage="partial",
    severity="high",
    severity_rationale=(
        "Shared root logins remove individual accountability and give an attacker full control."
    ),
    target_type="ssh_host",
    collector="sshd_effective_config",
)
def ssh_no_root_login(ev: dict, profile: Profile, now: datetime):
    value = ev["config"].get("permitrootlogin")
    observed = {"permitrootlogin": value}
    expected = {"permitrootlogin": "no"}
    if value != "no":
        return failed(f"PermitRootLogin is '{value}'", observed, expected)
    return passed("PermitRootLogin is 'no'", observed, expected)


@check(
    id="CHK-SSH-003",
    title="SSH limits authentication attempts per connection",
    requirements=ACCESS,
    coverage="partial",
    severity="low",
    severity_rationale="Slows guessing, but is a minor control compared with key-only auth.",
    target_type="ssh_host",
    collector="sshd_effective_config",
)
def ssh_max_auth_tries(ev: dict, profile: Profile, now: datetime):
    value = int(ev["config"]["maxauthtries"])
    limit = profile.ssh.max_auth_tries
    observed = {"maxauthtries": value}
    expected = {"maxauthtries_at_most": limit}
    if value > limit:
        return failed(f"MaxAuthTries is {value}", observed, expected)
    return passed(f"MaxAuthTries is {value}", observed, expected)
