"""Assemble a scan run into the structure the report (and the narrative) is built from.

Everything here is deterministic: counts, groupings, orderings and gap lists come
from findings.json and verdicts.json, never from a model.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from nis2scan.models import CheckStatus, Finding, RequirementVerdict, Verdict
from nis2scan.registry import CHECKS, COLLECTORS, load_all
from nis2scan.report.plain import explain

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
# How a check's assets are named in the report, by target section.
ASSET_KINDS = {
    "web": "web endpoints",
    "ssh": "SSH hosts",
    "idp": "identity providers",
    "logs": "log stores",
    "backup": "backup repositories",
    "docker": "Docker projects",
    "documents": "document sets",
}
NIS2_POINTS = [f"21(2)({p})" for p in "abcdefghij"] + ["23(4)"]

# Short names and icons for the measure map. The legal titles stay in the tables.
MEASURES = {
    "21(2)(a)": ("Risk analysis and security policies", "policy"),
    "21(2)(b)": ("Incident handling", "incident"),
    "21(2)(c)": ("Business continuity and backups", "backup"),
    "21(2)(d)": ("Supply chain security", "supply"),
    "21(2)(e)": ("Secure development and vulnerability handling", "code"),
    "21(2)(f)": ("Checking that the measures work", "gauge"),
    "21(2)(g)": ("Cyber hygiene and training", "training"),
    "21(2)(h)": ("Cryptography and encryption", "lock"),
    "21(2)(i)": ("Access control and asset management", "access"),
    "21(2)(j)": ("Multi-factor authentication", "mfa"),
    "23(4)": ("Reporting incidents to the CSIRT", "report"),
}


def topic(requirement_ids: list[str]) -> str:
    """The NIS2 measure a check falls under: that of its first NIS2-level requirement."""
    for req_id in requirement_ids:
        if match := re.fullmatch(r"REQ-NIS2-(\d+)\.(\d+)(?:\.([A-Z]))?", req_id):
            article, paragraph, point = match.groups()
            key = f"{article}({paragraph})" + (f"({point.lower()})" if point else "")
            if key in MEASURES:
                return MEASURES[key][0]
    return ""


def nis2_points(article: str) -> list[str]:
    """'21(2)(i), (j)' -> ['21(2)(i)', '21(2)(j)']; '23(4)' -> ['23(4)']."""
    match = re.match(r"(\d+\(\d+\))(.*)", article)
    if not match:
        return [article]
    base, rest = match.groups()
    letters = re.findall(r"\(([a-z])\)", rest)
    return [f"{base}({x})" for x in letters] or [base]


@dataclass
class Breach:
    """A legal requirement that a failing finding shows is not satisfied."""

    requirement_id: str
    title: str
    provision: str
    nis2_article: str
    quote: str


@dataclass
class AssetResult:
    """A check's result on one asset."""

    asset: str
    status: str
    message: str
    observed: dict
    expected: dict
    evidence_ref: str | None
    evidence_sha256: str | None
    found: str | None = None
    should: str | None = None


@dataclass
class Gap:
    """One failing check: the problem to fix, and every provision it breaches.

    Gaps are organised by check rather than by requirement, because one
    technical problem often breaches several provisions (e.g. an NIS2 article
    and the CIR points detailing it), and remediation belongs to the problem.

    A check runs once per asset. The top-level result fields describe the first
    failing asset; `assets` holds the result on every asset the check ran on.
    """

    finding_id: str  # the check ID
    title: str
    severity: str
    message: str
    observed: dict
    expected: dict
    evidence_ref: str | None
    evidence_sha256: str | None
    action: str  # what to do, in plain words (from the check's metadata)
    effort: str
    why: str  # the check's severity rationale, shown when there is no narrative
    found: str | None = None  # plain-language restatement of observed/expected
    should: str | None = None
    topic: str = ""  # the NIS2 measure the gap falls under, e.g. "Incident handling"
    asset: str | None = None  # the asset the top-level fields describe
    asset_kind: str = ""  # e.g. "web endpoints"
    assets: list[AssetResult] = field(default_factory=list)
    breaches: list[Breach] = field(default_factory=list)

    @property
    def failing_assets(self) -> list[AssetResult]:
        return [a for a in self.assets if a.status == CheckStatus.FAIL]


@dataclass
class ArticleRow:
    point: str
    title: str
    verdict: str  # the NIS2-level requirement's verdict
    detailed: int = 0  # CIR requirements under this point in the catalog
    detailed_not_satisfied: int = 0
    detailed_assessed: int = 0
    short_title: str = ""
    icon: str = ""


# Evidence paths are not useful to the model, and the presentation fields are
# written by hand: the narrative is validated against the scan's own values only.
_NOT_FOR_NARRATIVE = (
    "evidence_ref",
    "evidence_sha256",
    "action",
    "effort",
    "why",
    "found",
    "should",
    "topic",
    "asset",
    "asset_kind",
    "assets",
)


def _narrative_gap(g: Gap) -> dict:
    gap = {k: v for k, v in asdict(g).items() if k not in _NOT_FOR_NARRATIVE}
    # With several assets, the model needs every failing one. With one, the gap is
    # left exactly as it was before assets existed, so earlier measurements still hold.
    if len(g.assets) > 1:
        gap["failing_assets"] = [
            {"asset": a.asset, "message": a.message, "observed": a.observed, "expected": a.expected}
            for a in g.failing_assets
        ]
        gap["assets_checked"] = len(g.assets)
    return gap


@dataclass
class ReportData:
    target: str
    started_at: str
    tool: str
    profile_sha256: str
    check_counts: dict[str, int]
    verdict_counts: dict[str, int]
    articles: list[ArticleRow]
    gaps: list[Gap]
    findings: list[dict]  # one per check and asset
    verdicts: list[dict]
    not_assessed: list[dict] = field(default_factory=list)
    multi_asset: bool = False  # some check ran on more than one asset
    assets: list[dict] = field(default_factory=list)  # from scan.json; empty in older runs
    engagement: dict | None = None  # the agreed scope, from scan.json

    def narrative_input(self) -> dict:
        """The only information the narrative model is given."""
        return {
            "target": self.target,
            "scan_time": self.started_at,
            "requirement_verdicts": self.verdict_counts,
            "checks": self.check_counts,
            "gaps": [_narrative_gap(g) for g in self.gaps],
        }


def check_status_of(findings: list[Finding]) -> CheckStatus:
    """A check's overall status across its assets: it fails if it fails anywhere."""
    for status in (CheckStatus.FAIL, CheckStatus.ERROR, CheckStatus.PASS):
        if any(f.status == status for f in findings):
            return status
    return CheckStatus.NOT_APPLICABLE


def load_run(run_dir: Path) -> ReportData:
    load_all()
    scan = json.loads((run_dir / "scan.json").read_text())
    findings = [
        Finding.model_validate(f) for f in json.loads((run_dir / "findings.json").read_text())
    ]
    verdicts = [
        RequirementVerdict.model_validate(v)
        for v in json.loads((run_dir / "verdicts.json").read_text())
    ]
    evidence_sha = scan.get("evidence_sha256", {})

    def evidence_hash(ref: str | None) -> str | None:
        # Keys are "collector/asset" (or "collector" in runs from before assets existed).
        return (
            evidence_sha.get(ref.removeprefix("evidence/").removesuffix(".json")) if ref else None
        )

    def result(f: Finding) -> AssetResult:
        plain = (
            explain(f.check_id, f.observed, f.expected) if f.status == CheckStatus.FAIL else None
        )
        return AssetResult(
            asset=f.asset or "",
            status=f.status.value,
            message=f.message,
            observed=f.observed,
            expected=f.expected,
            evidence_ref=f.evidence_ref,
            evidence_sha256=evidence_hash(f.evidence_ref),
            found=plain.found if plain else None,
            should=plain.should if plain else None,
        )

    by_check: dict[str, list[Finding]] = {}
    for f in sorted(findings, key=lambda f: (f.check_id, f.asset or "")):
        by_check.setdefault(f.check_id, []).append(f)

    def gap(f: Finding) -> Gap:
        """The report entry for a check, described by finding `f` (one of its assets)."""
        check = CHECKS.get(f.check_id)
        meta = check.meta if check else None
        r = result(f)
        return Gap(
            finding_id=f.check_id,
            title=meta.title if meta else f.check_id,
            severity=meta.severity.value if meta else "medium",
            message=f.message,
            observed=f.observed,
            expected=f.expected,
            evidence_ref=f.evidence_ref,
            evidence_sha256=r.evidence_sha256,
            action=meta.action if meta else f.message,
            effort=meta.effort.value if meta else "change",
            why=meta.severity_rationale if meta else "",
            topic=topic(meta.requirements) if meta else "",
            found=r.found,
            should=r.should,
            asset=f.asset,
            asset_kind=ASSET_KINDS.get(COLLECTORS[check.collector].requires, "") if check else "",
            assets=[result(x) for x in by_check[f.check_id] if x.asset is not None],
        )

    gaps = {}
    for check_id, check_findings in by_check.items():
        failing = [f for f in check_findings if f.status == CheckStatus.FAIL]
        if failing:
            gaps[check_id] = gap(failing[0])
    for v in verdicts:
        if v.verdict != Verdict.NOT_SATISFIED:
            continue
        for check_id in v.check_ids:
            if check_id in gaps:
                gaps[check_id].breaches.append(
                    Breach(v.requirement_id, v.title, v.provision, v.nis2_article, v.quote)
                )
    for g in gaps.values():  # the NIS2 article first, then the CIR points detailing it
        g.breaches.sort(
            key=lambda b: (not b.requirement_id.startswith("REQ-NIS2-"), b.requirement_id)
        )
    ordered = sorted(gaps.values(), key=lambda g: (SEVERITY_ORDER.index(g.severity), g.finding_id))
    check_status = {c: check_status_of(fs) for c, fs in by_check.items()}

    articles = {}
    for v in verdicts:
        if v.requirement_id.startswith("REQ-NIS2-"):
            for point in nis2_points(v.nis2_article):
                short, icon = MEASURES.get(point, (v.title, "policy"))
                articles[point] = ArticleRow(
                    point, v.title, v.verdict.value, short_title=short, icon=icon
                )
    for v in verdicts:
        if v.requirement_id.startswith("REQ-NIS2-"):
            continue
        for point in nis2_points(v.nis2_article):
            row = articles.get(point)
            if row:
                row.detailed += 1
                row.detailed_assessed += v.verdict != Verdict.NOT_ASSESSED
                row.detailed_not_satisfied += v.verdict == Verdict.NOT_SATISFIED

    return ReportData(
        target=scan["target"],
        started_at=scan["started_at"],
        tool=scan["tool"],
        profile_sha256=scan["profile_sha256"],
        check_counts={s.value: sum(v == s for v in check_status.values()) for s in CheckStatus},
        verdict_counts={s.value: sum(v.verdict == s for v in verdicts) for s in Verdict},
        articles=[articles[p] for p in NIS2_POINTS if p in articles],
        gaps=ordered,
        findings=[
            {**f.model_dump(mode="json"), **asdict(gap(f)), "asset": f.asset}
            for check_findings in by_check.values()
            for f in check_findings
        ],
        verdicts=[v.model_dump(mode="json") for v in verdicts if v.verdict != Verdict.NOT_ASSESSED],
        not_assessed=[
            v.model_dump(mode="json") for v in verdicts if v.verdict == Verdict.NOT_ASSESSED
        ],
        multi_asset=any(len(fs) > 1 for fs in by_check.values()),
        assets=scan.get("assets", []),
        engagement=scan.get("engagement"),
    )
