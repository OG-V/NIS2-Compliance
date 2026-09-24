"""Run all checks against a target and roll the findings up per requirement."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from nis2scan import __version__
from nis2scan.config import Profile, Target
from nis2scan.models import (
    CheckStatus,
    Finding,
    Requirement,
    RequirementVerdict,
    Testability,
    Verdict,
    rollup,
)
from nis2scan.registry import CHECKS, COLLECTORS, Context, load_all


@dataclass
class ScanResult:
    target: str
    started_at: datetime
    findings: list[Finding]
    verdicts: list[RequirementVerdict]
    evidence: dict[str, dict | Exception]


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
    findings = [_run_check(check_id, target, profile, ctx, now) for check_id in sorted(CHECKS)]
    verdicts = [_verdict(req, findings) for req in requirements]
    return ScanResult(target.name, now, findings, verdicts, ctx.evidence())


def _run_check(check_id: str, target: Target, profile: Profile, ctx: Context, now: datetime):
    chk = CHECKS[check_id]
    col = COLLECTORS[chk.collector]
    base = {"check_id": check_id, "target": target.name}

    if getattr(target, col.requires) is None:
        return Finding(
            **base,
            status=CheckStatus.NOT_APPLICABLE,
            message=f"target has no '{col.requires}' section",
            collected_at=now,
        )
    try:
        evidence = ctx.collect(chk.collector)
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
        evidence_ref=f"evidence/{chk.collector}.json",
        collected_at=datetime.fromisoformat(evidence["_collected_at"]),
    )


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
        failing = [f.check_id for f in relevant if f.status == CheckStatus.FAIL]
        reason = f"failed: {', '.join(failing)}"
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
    for name, evidence in sorted(result.evidence.items()):
        body = (
            {"_error": f"{type(evidence).__name__}: {evidence}"}
            if isinstance(evidence, Exception)
            else evidence
        )
        data = json.dumps(body, indent=2, sort_keys=True, default=str).encode()
        (run_dir / "evidence" / f"{name}.json").write_bytes(data)
        evidence_hashes[name] = hashlib.sha256(data).hexdigest()

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
