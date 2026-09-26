"""The scan pipeline end to end, fed with recorded evidence."""

import json
from pathlib import Path

import pytest
from conftest import ROOT, FixtureContext, collected_at, load_evidence

from nis2scan.catalog import load_requirements
from nis2scan.config import load_profile, load_target
from nis2scan.extract.sources import NIS2
from nis2scan.models import CheckStatus, Verdict
from nis2scan.models import Testability as Kind
from nis2scan.scan import run_scan, write_results

PROFILE_PATH = ROOT / "catalog" / "profile.yaml"
# The scanner tests cover the hand-authored NIS2 requirements that the checks map to;
# extracted CIR 2024/2690 requirements have no checks yet.
REQUIREMENTS = [
    r
    for r in load_requirements(ROOT / "catalog" / "requirements", include_drafts=True)
    if r.source.instrument == NIS2.instrument
]


def scan(lab_profile: str, target_path: Path = ROOT / "lab" / "target.yaml"):
    target = load_target(target_path)
    now = collected_at(load_evidence(lab_profile, "tls_probe"))
    return run_scan(
        target,
        load_profile(PROFILE_PATH),
        REQUIREMENTS,
        now=now,
        context=FixtureContext(target, lab_profile),
    )


@pytest.mark.parametrize(
    "lab_profile, technical_verdict",
    [("weak", Verdict.NOT_SATISFIED), ("hardened", Verdict.PARTIALLY_EVIDENCED)],
)
def test_verdicts(lab_profile, technical_verdict):
    result = scan(lab_profile)
    reviewed = {
        r["requirement"]: r["verdict"]
        for r in load_evidence(lab_profile, "evidence_register")["reviews"]
    }
    for v in result.verdicts:
        if v.requirement_id in reviewed:  # organisational: the reviewer's decision
            assert (v.basis, v.verdict) == ("document", reviewed[v.requirement_id]), v.reason
        elif v.testability == Kind.ORGANISATIONAL:
            assert (v.basis, v.verdict) == ("none", Verdict.NOT_ASSESSED), v.requirement_id
        else:
            assert (v.basis, v.verdict) == ("checks", technical_verdict), (
                v.requirement_id,
                v.reason,
            )


def test_missing_target_section_is_not_applicable(tmp_path):
    target_file = tmp_path / "target.yaml"
    target_file.write_text("name: web-only\nweb: {host: 127.0.0.1, http_port: 1, https_port: 2}\n")
    result = scan("hardened", target_file)
    by_check = {f.check_id: f.status for f in result.findings}
    assert by_check["CHK-TLS-001"] == CheckStatus.PASS
    assert by_check["CHK-SSH-001"] == CheckStatus.NOT_APPLICABLE
    idp_verdict = next(v for v in result.verdicts if v.requirement_id == "REQ-NIS2-21.2.J")
    assert idp_verdict.verdict == Verdict.NOT_ASSESSED


def test_collector_failure_becomes_error_finding():
    target = load_target(ROOT / "lab" / "target.yaml")

    class Broken(FixtureContext):
        def _run(self, name, asset):
            if name == "idp_config":
                raise ConnectionRefusedError("idp down")
            return super()._run(name, asset)

    result = run_scan(
        target, load_profile(PROFILE_PATH), REQUIREMENTS, context=Broken(target, "hardened"),
        now=collected_at(load_evidence("hardened", "tls_probe")),
    )  # fmt: skip
    idp = [f for f in result.findings if f.check_id in ("CHK-IDP-001", "CHK-IDP-002")]
    assert all(f.status == CheckStatus.ERROR and "idp down" in f.message for f in idp)
    mfa = next(v for v in result.verdicts if v.requirement_id == "REQ-NIS2-21.2.J")
    assert mfa.verdict == Verdict.NOT_ASSESSED  # an error is never counted as a pass


def test_write_results(tmp_path):
    run_dir = write_results(scan("weak"), tmp_path, PROFILE_PATH)
    meta = json.loads((run_dir / "scan.json").read_text())
    findings = json.loads((run_dir / "findings.json").read_text())
    # 17 checks; log retention and the two backup checks each run on two assets.
    assert len(findings) == 20
    for f in findings:
        assert (run_dir / f["evidence_ref"]).exists()
    files = (run_dir / "evidence").rglob("*.json")
    assert set(meta["evidence_sha256"]) == {
        str(p.relative_to(run_dir / "evidence").with_suffix("")) for p in files
    }
    assert "tls_probe/portal" in meta["evidence_sha256"]  # one file per asset
