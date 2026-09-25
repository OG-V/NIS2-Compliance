"""Compare two scans of the same target: what was fixed, what is still open, what is new.

Like the gap report, everything here is deterministic. Both scans are loaded with
load_run(), so the comparison uses exactly the figures each gap report shows.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from nis2scan.report.data import MEASURES, NIS2_POINTS, SEVERITY_ORDER, ReportData, load_run

FAIL, PASS = "fail", "pass"


@dataclass
class CheckChange:
    check_id: str
    title: str
    severity: str
    action: str
    effort: str
    topic: str
    before: str | None  # check status, or None if the check was not in that scan
    after: str | None
    before_text: str  # plain "found" line if the check failed, else its message
    after_text: str


@dataclass
class MeasureChange:
    point: str
    short_title: str
    icon: str
    before: str | None  # the NIS2-level requirement's verdict
    after: str | None
    before_not_satisfied: int  # CIR requirements under this point that are not satisfied
    after_not_satisfied: int


@dataclass
class Comparison:
    target: str
    before_started_at: str
    after_started_at: str
    before_verdicts: dict[str, int]
    after_verdicts: dict[str, int]
    before_severities: dict[str, int]
    after_severities: dict[str, int]
    before_failing: int
    fixed: list[CheckChange] = field(default_factory=list)
    still_open: list[CheckChange] = field(default_factory=list)
    new: list[CheckChange] = field(default_factory=list)
    unresolved: list[CheckChange] = field(default_factory=list)  # errors, added or removed checks
    still_passing: int = 0
    measures: list[MeasureChange] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _severities(data: ReportData) -> dict[str, int]:
    return {s: sum(g.severity == s for g in data.gaps) for s in SEVERITY_ORDER}


def _text(finding: dict | None) -> str:
    if finding is None:
        return "Not part of this scan."
    return (finding["found"] if finding["status"] == FAIL else None) or finding["message"]


def _warnings(before: ReportData, after: ReportData) -> list[str]:
    warnings = []
    if before.target != after.target:
        warnings.append(f"The scans are of different targets ({before.target} and {after.target}).")
    if after.started_at < before.started_at:
        warnings.append("The 'after' scan is older than the 'before' scan.")
    if before.profile_sha256 != after.profile_sha256:
        warnings.append(
            "The organisation's profile changed between the scans, so some changes may come "
            "from different thresholds rather than from the system."
        )
    n_before, n_after = sum(before.verdict_counts.values()), sum(after.verdict_counts.values())
    if n_before != n_after:
        warnings.append(
            f"The requirement catalog changed between the scans ({n_before} and {n_after} "
            "requirements), so requirement counts are not directly comparable."
        )
    if before.tool != after.tool:
        warnings.append(
            f"The scans were made with different versions ({before.tool}, {after.tool})."
        )
    return warnings


def compare(before: ReportData, after: ReportData) -> Comparison:
    result = Comparison(
        target=after.target,
        before_started_at=before.started_at,
        after_started_at=after.started_at,
        before_verdicts=before.verdict_counts,
        after_verdicts=after.verdict_counts,
        before_severities=_severities(before),
        after_severities=_severities(after),
        before_failing=before.check_counts[FAIL],
        warnings=_warnings(before, after),
    )
    old = {f["check_id"]: f for f in before.findings}
    new = {f["check_id"]: f for f in after.findings}
    for check_id in sorted(old.keys() | new.keys()):
        b, a = old.get(check_id), new.get(check_id)
        latest = a or b
        change = CheckChange(
            check_id=check_id,
            title=latest["title"],
            severity=latest["severity"],
            action=latest["action"],
            effort=latest["effort"],
            topic=latest["topic"],
            before=b["status"] if b else None,
            after=a["status"] if a else None,
            before_text=_text(b),
            after_text=_text(a),
        )
        if change.before == FAIL and change.after == PASS:
            result.fixed.append(change)
        elif change.before == FAIL and change.after == FAIL:
            result.still_open.append(change)
        elif change.after == FAIL:
            result.new.append(change)
        elif change.before == PASS and change.after == PASS:
            result.still_passing += 1
        else:
            result.unresolved.append(change)
    for changes in (result.fixed, result.still_open, result.new, result.unresolved):
        changes.sort(key=lambda c: (SEVERITY_ORDER.index(c.severity), c.check_id))

    rows_before = {a.point: a for a in before.articles}
    rows_after = {a.point: a for a in after.articles}
    for point in NIS2_POINTS:
        b, a = rows_before.get(point), rows_after.get(point)
        if not (a or b):
            continue
        short, icon = MEASURES[point]
        result.measures.append(
            MeasureChange(
                point,
                short,
                icon,
                b.verdict if b else None,
                a.verdict if a else None,
                b.detailed_not_satisfied if b else 0,
                a.detailed_not_satisfied if a else 0,
            )
        )
    return result


_env = Environment(
    loader=PackageLoader("nis2scan.report", "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    undefined=StrictUndefined,
)


def render_comparison(
    before_dir: Path, after_dir: Path, out: Path
) -> tuple[Path, Path, Comparison]:
    """Write the comparison as HTML at `out` and as JSON next to it."""
    comparison = compare(load_run(before_dir), load_run(after_dir))
    html = _env.get_template("compare.html.j2").render(
        c=comparison, before_name=before_dir.name, after_name=after_dir.name
    )
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html, encoding="utf-8")
    json_path = out.with_suffix(".json")
    json_path.write_text(json.dumps(asdict(comparison), indent=2) + "\n")
    return out, json_path, comparison
