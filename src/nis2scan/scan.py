"""Run all checks against a target and roll the findings up per requirement."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from nis2scan import __version__
from nis2scan.config import Asset, Profile, Target, slug
from nis2scan.models import (
    CheckStatus,
    Finding,
    Requirement,
    RequirementVerdict,
    Testability,
    Verdict,
    rollup,
)
from nis2scan.registry import CHECKS, COLLECTORS, Context, NotApplicable, load_all


@dataclass
class ScanResult:
    target: str
    started_at: datetime
    findings: list[Finding]
    verdicts: list[RequirementVerdict]
    evidence: dict[tuple[str, str], dict | Exception]  # keyed by (collector, asset name)


def run_scan(
    target: Target,
    profile: Profile,
    requirements: list[Requirement],
    now: datetime | None = None,
    context: Context | None = None,
) -> ScanResult:
    load_all()
    now = now or datetime.now(UTC)
    ctx = context or Context(target)
    findings = [
        finding
        for check_id in sorted(CHECKS)
        for finding in _run_check(check_id, target, profile, ctx, now)
    ]
    verdicts = [_verdict(req, findings) for req in requirements]
    return ScanResult(target.name, now, findings, verdicts, ctx.evidence())


def evidence_path(collector: str, asset: str) -> str:
    return f"evidence/{collector}/{slug(asset)}.json"


def _run_check(
    check_id: str, target: Target, profile: Profile, ctx: Context, now: datetime
) -> list[Finding]:
    """One finding per asset in the section the check's collector needs."""
    section = COLLECTORS[CHECKS[check_id].collector].requires
    assets = target.assets(section)
    if not assets:
        return [
            Finding(
                check_id=check_id,
                target=target.name,
                status=CheckStatus.NOT_APPLICABLE,
                message=f"target has no '{section}' section",
                collected_at=now,
            )
        ]
    return [_run_check_on(check_id, asset, target, profile, ctx, now) for asset in assets]


def _run_check_on(
    check_id: str, asset: Asset, target: Target, profile: Profile, ctx: Context, now: datetime
) -> Finding:
    chk = CHECKS[check_id]
    base = {"check_id": check_id, "target": target.name, "asset": asset.name}
    try:
        evidence = ctx.collect(chk.collector, asset)
    except NotApplicable as exc:
        return Finding(
            **base, status=CheckStatus.NOT_APPLICABLE, message=str(exc), collected_at=now
        )
    except Exception as exc:  # noqa: BLE001 - reported as an 'error' finding
        return Finding(
            **base,
            status=CheckStatus.ERROR,
            message=f"collector {chk.collector} failed: {type(exc).__name__}: {exc}",
            collected_at=now,
        )
    try:
        result = chk.evaluate(evidence, profile, now)
    except Exception as exc:  # noqa: BLE001 - reported as an 'error' finding
        result = None
        message = f"evaluation failed: {type(exc).__name__}: {exc}"
    return Finding(
        **base,
        status=result.status if result else CheckStatus.ERROR,
        message=result.message if result else message,
        observed=result.observed if result else {},
        expected=result.expected if result else {},
        evidence_ref=evidence_path(chk.collector, asset.name),
        collected_at=datetime.fromisoformat(evidence["_collected_at"]),
    )


def _assets_checked(findings: list[Finding], finding: Finding) -> set[str | None]:
    """The assets a check ran against, to name the asset only when there are several."""
    return {f.asset for f in findings if f.check_id == finding.check_id}


def _verdict(req: Requirement, findings: list[Finding]) -> RequirementVerdict:
    checks = [c.meta for c in CHECKS.values() if req.id in c.meta.requirements]
    relevant = [f for f in findings if f.check_id in {c.id for c in checks}]
    verdict = rollup(checks, relevant)

    if not checks:
        reason = (
            "organisational requirement: needs audit, not automated checks"
            if req.testability == Testability.ORGANISATIONAL
            else "no checks implemented yet"
        )
    elif verdict == Verdict.NOT_SATISFIED:
        failing = [f for f in relevant if f.status == CheckStatus.FAIL]
        reason = "failed: " + ", ".join(
            dict.fromkeys(
                f.check_id + (f" on {f.asset}" if len(_assets_checked(relevant, f)) > 1 else "")
                for f in failing
            )
        )
    elif verdict == Verdict.NOT_ASSESSED:
        reason = "checks could not run (see findings with status error / not_applicable)"
    elif verdict == Verdict.PARTIALLY_EVIDENCED:
        reason = "all checks passed, but together they cover only part of the requirement"
    else:
        reason = "all checks passed"

    return RequirementVerdict(
        requirement_id=req.id,
        title=req.title,
        provision=f"{req.source.instrument}, {req.source.provision}",
        nis2_article=req.source.nis2_article,
        quote=req.source.quote,
        testability=req.testability,
        review_status=req.review.status,
        verdict=verdict,
        check_ids=[c.id for c in checks],
        reason=reason,
    )


def write_results(result: ScanResult, out_dir: Path, profile_path: Path) -> Path:
    """Write findings, verdicts and raw evidence to a new run directory."""
    stamp = result.started_at.strftime("%Y%m%dT%H%M%SZ")
    run_dir = out_dir / f"{result.target}-{stamp}"
    (run_dir / "evidence").mkdir(parents=True, exist_ok=False)

    evidence_hashes = {}
    for (collector, asset), evidence in sorted(result.evidence.items()):
        body = (
            {"_error": f"{type(evidence).__name__}: {evidence}"}
            if isinstance(evidence, Exception)
            else evidence
        )
        data = json.dumps(body, indent=2, sort_keys=True, default=str).encode()
        ref = evidence_path(collector, asset)
        (run_dir / ref).parent.mkdir(exist_ok=True)
        (run_dir / ref).write_bytes(data)
        evidence_hashes[ref.removeprefix("evidence/").removesuffix(".json")] = hashlib.sha256(
            data
        ).hexdigest()

    def dump(name: str, obj) -> None:
        (run_dir / name).write_text(json.dumps(obj, indent=2, default=str) + "\n")

    dump("findings.json", [f.model_dump(mode="json") for f in result.findings])
    dump("verdicts.json", [v.model_dump(mode="json") for v in result.verdicts])
    dump(
        "scan.json",
        {
            "tool": f"nis2scan {__version__}",
            "target": result.target,
            "started_at": result.started_at.isoformat(),
            "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
            "evidence_sha256": evidence_hashes,
        },
    )
    return run_dir
