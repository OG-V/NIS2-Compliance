"""Logging (Art. 21(2)(b)), backups (21(2)(c)), assets (21(2)(i)), vulnerabilities (21(2)(e))."""

from datetime import date, datetime, timedelta

from nis2scan.adapters.logging import LogRetentionEvidence
from nis2scan.config import Profile
from nis2scan.registry import check, failed, passed


@check(
    id="CHK-LOG-001",
    title="Central logs are kept at least as long as the profile requires",
    requirements=[
        "REQ-NIS2-21.2.B",
        "REQ-CIR2690-3.2.5-01",  # logs kept for a predefined period
    ],
    coverage="partial",
    severity="medium",
    severity_rationale="Logs deleted too early make an incident impossible to investigate or report.",
    action="Keep logs for as long as the policy requires",
    effort="quick",
    target_type="log_store",
    collector="log_retention",
)
def log_retention(ev: dict, profile: Profile, now: datetime):
    """The shortest retention in the store decides: it applies to some of the logs."""
    store = LogRetentionEvidence.model_validate(ev["retention"])
    minimum = profile.logging.min_retention_days
    expected = {"min_retention_days": minimum}
    shortest = store.shortest
    if shortest is None:
        observed = {"retention_days": None, "scopes": len(store.scopes)}
        return passed("Logs are never deleted; they are kept indefinitely", observed, expected)
    observed = {"retention_days": shortest.retention_days, "source": shortest.source}
    where = ""
    if len(store.scopes) > 1:  # name the scope only when there is a choice
        observed["scope"] = shortest.name
        where = f" ({shortest.name})"
    n = shortest.retention_days
    span = f"{n} day{'' if n == 1 else 's'}{where}"
    if n < minimum:
        return failed(f"Logs are deleted after {span}", observed, expected)
    return passed(f"Logs are kept for {span}", observed, expected)


@check(
    id="CHK-BAK-001",
    title="A recent backup snapshot exists",
    requirements=[
        "REQ-NIS2-21.2.C",
        "REQ-CIR2690-4.2.1-01",  # backup copies maintained
    ],
    coverage="partial",
    severity="high",
    severity_rationale="Without recent backups, ransomware or failure causes permanent data loss.",
    action="Restart automatic backups",
    effort="change",
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
    requirements=[
        "REQ-NIS2-21.2.I",
        "REQ-CIR2690-12.4.1-01",  # complete, accurate inventory
    ],
    coverage="partial",
    severity="medium",
    severity_rationale="Unknown services go unpatched and unmonitored.",
    action="Add every running service to the asset inventory",
    effort="quick",
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
    requirements=[
        "REQ-NIS2-21.2.E",
        "REQ-CIR2690-6.10.1-03",  # vulnerabilities managed
        "REQ-CIR2690-6.10.2-03",  # critical ones addressed without undue delay
        "REQ-CIR2690-6.6.1-02",  # patches applied in reasonable time
    ],
    coverage="partial",
    severity="high",
    severity_rationale="Known, fixable critical vulnerabilities are the most common way in.",
    action="Update software that has known critical flaws",
    effort="project",
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
