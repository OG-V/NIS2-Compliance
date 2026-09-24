"""Documentary checks on the incident response plan (Art. 23(4), Art. 21(2)(b))."""

import re
from datetime import date, datetime

from nis2scan.config import Profile
from nis2scan.registry import check, failed, passed

# Keyword presence is a proxy: it shows the plan mentions each reporting stage,
# not that the procedure is any good. Hence coverage "partial".
REPORTING_ELEMENTS = {
    "24h early warning": r"\b24\s*(hours|h)\b",
    "72h incident notification": r"\b72\s*(hours|h)\b",
    "one-month final report": r"\b(one|1)\s+month\b",
    "CSIRT contact": r"\bCSIRT\b",
}


@check(
    id="CHK-DOC-001",
    title="Incident response plan covers the NIS2 reporting stages",
    requirements=["REQ-NIS2-23.4"],
    coverage="partial",
    severity="medium",
    severity_rationale=(
        "Missing a reporting deadline is itself a breach of Art. 23, separate from the incident."
    ),
    target_type="document",
    collector="ir_plan",
)
def ir_plan_reporting(ev: dict, profile: Profile, now: datetime):
    missing = [
        name
        for name, pattern in REPORTING_ELEMENTS.items()
        if not re.search(pattern, ev["text"], re.IGNORECASE)
    ]
    observed = {"document": ev["document"], "missing": missing}
    expected = {"mentions": list(REPORTING_ELEMENTS)}
    if missing:
        return failed(f"Plan does not mention: {', '.join(missing)}", observed, expected)
    return passed("Plan mentions every reporting stage and the CSIRT", observed, expected)


@check(
    id="CHK-DOC-002",
    title="Incident response plan has been reviewed recently",
    requirements=["REQ-NIS2-21.2.B"],
    coverage="partial",
    severity="low",
    severity_rationale="A stale plan lists wrong contacts and outdated systems when it is needed.",
    target_type="document",
    collector="ir_plan",
)
def ir_plan_reviewed(ev: dict, profile: Profile, now: datetime):
    max_age = profile.incident_response.max_review_age_days
    expected = {"max_review_age_days": max_age}
    match = re.search(r"Last reviewed:\s*(\d{4}-\d{2}-\d{2})", ev["text"])
    if not match:
        return failed("Plan has no 'Last reviewed:' date", {"document": ev["document"]}, expected)
    reviewed = date.fromisoformat(match.group(1))
    age = (now.date() - reviewed).days
    observed = {"document": ev["document"], "last_reviewed": reviewed.isoformat(), "age_days": age}
    if age > max_age:
        return failed(f"Plan was last reviewed {age} days ago", observed, expected)
    return passed(f"Plan was reviewed {age} days ago", observed, expected)
