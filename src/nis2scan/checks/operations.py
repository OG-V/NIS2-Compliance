"""Logging (Art. 21(2)(b)), backups (21(2)(c)), assets (21(2)(i)), vulnerabilities (21(2)(e))."""

import re
from datetime import date, datetime, timedelta

from nis2scan.config import Profile
from nis2scan.registry import check, failed, passed

DURATION_UNITS = {
    "ms": timedelta(milliseconds=1),
    "s": timedelta(seconds=1),
    "m": timedelta(minutes=1),
    "h": timedelta(hours=1),
    "d": timedelta(days=1),
    "w": timedelta(weeks=1),
    "y": timedelta(days=365),
}


def parse_duration(text: str) -> timedelta:
    """Parse a Prometheus/Loki duration such as '1w', '180d' or '1d12h'."""
    parts = re.findall(r"(\d+)(ms|s|m|h|d|w|y)", text)
    if not parts or "".join(n + u for n, u in parts) != text:
        raise ValueError(f"not a duration: {text!r}")
    return sum((int(n) * DURATION_UNITS[u] for n, u in parts), timedelta())


@check(
    id="CHK-LOG-001",
    title="Central logs are kept at least as long as the profile requires",
    requirements=["REQ-NIS2-21.2.B"],
    coverage="partial",
    severity="medium",
    severity_rationale="Logs deleted too early make an incident impossible to investigate or report.",
    target_type="log_store",
    collector="loki_config",
)
def log_retention(ev: dict, profile: Profile, now: datetime):
    period = ev["limits_config"]["retention_period"]
    enabled = ev["compactor"]["retention_enabled"]
    minimum = profile.logging.min_retention_days
    expected = {"min_retention_days": minimum}
    retention = parse_duration(period)
    if not enabled or retention == timedelta(0):
        observed = {"retention_enabled": enabled, "retention_period": period}
        return passed(
            "Retention deletion is disabled; logs are kept indefinitely", observed, expected
        )
    observed = {"retention_period": period, "retention_days": retention.days}
    if retention < timedelta(days=minimum):
        return failed(f"Logs are deleted after {retention.days} days", observed, expected)
    return passed(f"Logs are kept for {retention.days} days", observed, expected)


@check(
    id="CHK-BAK-001",
    title="A recent backup snapshot exists",
    requirements=["REQ-NIS2-21.2.C"],
    coverage="partial",
    severity="high",
    severity_rationale="Without recent backups, ransomware or failure causes permanent data loss.",
    target_type="backup_repository",
    collector="restic_snapshots",
)
def recent_backup(ev: dict, profile: Profile, now: datetime):
    max_age = timedelta(hours=profile.backup.max_age_hours)
    expected = {"max_age_hours": profile.backup.max_age_hours}
    if not ev["snapshots"]:
        return failed("No backup snapshots exist", {"snapshots": 0}, expected)
    newest = max(datetime.fromisoformat(s["time"]) for s in ev["snapshots"])
    age = now - newest
    observed = {
        "snapshots": len(ev["snapshots"]),
        "newest": newest.isoformat(),
        "age_hours": round(age.total_seconds() / 3600, 1),
    }
    if age > max_age:
        return failed(f"Newest backup is {age.days} days old", observed, expected)
    return passed("Newest backup is within the allowed age", observed, expected)


@check(
    id="CHK-AST-001",
    title="Every running service is in the asset inventory",
    requirements=["REQ-NIS2-21.2.I"],
    coverage="partial",
    severity="medium",
    severity_rationale="Unknown services go unpatched and unmonitored.",
    target_type="container_platform",
    collector="asset_inventory",
)
def services_inventoried(ev: dict, profile: Profile, now: datetime):
    undeclared = sorted(set(ev["running"]) - set(ev["declared"]))
    observed = {"undeclared_services": undeclared, "running": ev["running"]}
    expected = {"undeclared_services": []}
    if undeclared:
        return failed(f"Not in the inventory: {', '.join(undeclared)}", observed, expected)
    return passed(f"All {len(ev['running'])} running services are inventoried", observed, expected)


@check(
    id="CHK-VUL-001",
    title="No unaccepted, fixable vulnerability at the failing severity in running images",
    requirements=["REQ-NIS2-21.2.E"],
    coverage="partial",
    severity="high",
    severity_rationale="Known, fixable critical vulnerabilities are the most common way in.",
    target_type="container_platform",
    collector="image_vulnerabilities",
)
def no_fixable_vulnerabilities(ev: dict, profile: Profile, now: datetime):
    policy = profile.vulnerabilities
    exceptions = ev.get("risk_exceptions", [])
    active = {
        (e["vulnerability"], e["image"])
        for e in exceptions
        if date.fromisoformat(e["expires"]) >= now.date()
    }
    expired = sorted(
        e["vulnerability"] for e in exceptions if date.fromisoformat(e["expires"]) < now.date()
    )

    failing, accepted = {}, set()
    for image in ev["images"]:
        repository = image["image"].rsplit(":", 1)[0]
        for v in image["vulnerabilities"]:
            if v["severity"] not in policy.fail_on_severity:
                continue
            if policy.only_with_fix and not v["fixed"]:
                continue
            if (v["id"], repository) in active:
                accepted.add(v["id"])
            else:
                failing.setdefault(image["image"], set()).add(v["id"])

    observed = {
        "images_scanned": len(ev["images"]),
        "failing": {img: sorted(ids) for img, ids in sorted(failing.items())},
        "accepted_risks": sorted(accepted),
    }
    if expired:
        observed["expired_exceptions"] = expired
    end_of_support = [i["image"] for i in ev["images"] if i["os_end_of_support"]]
    if end_of_support:
        observed["os_end_of_support"] = end_of_support
    expected = {"severities": policy.fail_on_severity, "only_with_fix": policy.only_with_fix}

    label = "/".join(policy.fail_on_severity)
    if failing:
        summary = ", ".join(
            f"{img} ({len(ids)})" for img, ids in sorted(failing.items(), key=lambda i: -len(i[1]))
        )
        return failed(f"Fixable {label} vulnerabilities in {summary}", observed, expected)
    suffix = f", {len(accepted)} covered by accepted risk exceptions" if accepted else ""
    return passed(f"No unaccepted fixable {label} vulnerabilities{suffix}", observed, expected)
