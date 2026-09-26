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

FAIL, PASS, NOT_APPLICABLE = "fail", "pass", "not_applicable"


@dataclass
class CheckChange:
    """One check on one asset, in both scans."""

    check_id: str
    asset: str | None  # None when the check had no asset (e.g. runs from before assets)
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
    before_failing: int  # failing results (check and asset) in the first scan
    multi_asset: bool = False
    fixed: list[CheckChange] = field(default_factory=list)
    still_open: list[CheckChange] = field(default_factory=list)
    new: list[CheckChange] = field(default_factory=list)
    unresolved: list[CheckChange] = field(default_factory=list)  # errors, added or removed checks
    still_passing: int = 0
    measures: list[MeasureChange] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    # Requirements with evidence, by basis (checks, document), and document-review verdicts.
    before_by_basis: dict[str, int] = field(default_factory=dict)
    after_by_basis: dict[str, int] = field(default_factory=dict)
    review_change: str = ""  # one sentence on how the document reviews changed, if any


def _severities(data: ReportData) -> dict[str, int]:
    """Failing results by severity. A check failing on two assets counts twice."""
    failing = [f for f in data.findings if f["status"] == FAIL]
    return {s: sum(f["severity"] == s for f in failing) for s in SEVERITY_ORDER}


def _pairs(before: ReportData, after: ReportData):
    """(before, after) finding pairs for the same check and asset.

    A check with a single result in both scans is paired whatever its asset is
    called, so a run from before assets were named still compares with a newer one.
    """
    by_check: dict[str, tuple[list[dict], list[dict]]] = {}
    for side, data in enumerate((before, after)):
        for f in data.findings:
            by_check.setdefault(f["check_id"], ([], []))[side].append(f)
    for check_id in sorted(by_check):
        old, new = by_check[check_id]
        if len(old) == 1 and len(new) == 1:
            yield old[0], new[0]
            continue
        old_by = {f.get("asset"): f for f in old}
        new_by = {f.get("asset"): f for f in new}
        for asset in sorted(old_by.keys() | new_by.keys(), key=lambda a: a or ""):
            yield old_by.get(asset), new_by.get(asset)


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


REVIEW_WORDS = [
    ("evidenced", "evidenced"),
    ("partially_evidenced", "partially evidenced"),
    ("not_satisfied", "not satisfied"),
    ("not_assessed", "no longer valid"),
]


def _reviewed(data: ReportData) -> dict[str, int]:
    """Verdicts resting on a document review, counted by verdict."""
    counts: dict[str, int] = {}
    for v in data.verdicts + data.not_assessed:
        if v.get("basis") == "document":
            counts[v["verdict"]] = counts.get(v["verdict"], 0) + 1
    return counts


def _review_change(before: dict[str, int], after: dict[str, int]) -> str:
    if not (before or after):
        return ""

    def words(counts):
        parts = [f"{counts[k]} {w}" for k, w in REVIEW_WORDS if counts.get(k)]
        if len(parts) > 1:
            return ", ".join(parts[:-1]) + " and " + parts[-1]
        return parts[0] if parts else "none"

    if before == after:
        return f"Document reviews: unchanged ({words(after)})."
    return f"Document reviews: {words(before)} before; {words(after)} now."


def compare(before: ReportData, after: ReportData) -> Comparison:
    result = Comparison(
        target=after.target,
        before_started_at=before.started_at,
        after_started_at=after.started_at,
        before_verdicts=before.verdict_counts,
        after_verdicts=after.verdict_counts,
        before_severities=_severities(before),
        after_severities=_severities(after),
        before_failing=sum(f["status"] == FAIL for f in before.findings),
        warnings=_warnings(before, after),
        multi_asset=before.multi_asset or after.multi_asset,
        before_by_basis=before.evidence_by_basis,
        after_by_basis=after.evidence_by_basis,
        review_change=_review_change(_reviewed(before), _reviewed(after)),
    )
    for b, a in _pairs(before, after):
        latest = a or b
        change = CheckChange(
            check_id=latest["check_id"],
            asset=latest.get("asset"),
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
        if {change.before, change.after} <= {NOT_APPLICABLE, None}:
            continue  # nothing to compare: the check did not apply in either scan
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
        changes.sort(key=lambda c: (SEVERITY_ORDER.index(c.severity), c.check_id, c.asset or ""))

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
