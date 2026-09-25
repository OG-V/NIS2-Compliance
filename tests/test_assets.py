"""Targets with several assets of a kind, fed with recorded evidence per asset."""

import json

import pytest
import yaml
from conftest import PROFILE, ROOT, FixtureContext, collected_at, load_evidence, scan_run
from pydantic import ValidationError

from nis2scan.catalog import load_requirements
from nis2scan.config import Target, load_profile, load_target
from nis2scan.models import CheckStatus, Verdict
from nis2scan.report.compare import compare
from nis2scan.report.data import load_run
from nis2scan.report.render import render
from nis2scan.scan import run_scan, write_results

LAB = yaml.safe_load((ROOT / "lab" / "target.yaml").read_text())

# Two web endpoints and two SSH hosts. "portal" and "jump" serve the weak lab's
# recorded evidence, "shop" and "bastion" the hardened lab's. "bastion" has no
# container, so only its network-visible SSH check can run.
MIXED = {
    **LAB,
    "name": "mixed-estate",
    "env_file": None,
    "web": [
        {"name": "portal", "host": "10.0.0.1", "http_port": 80, "https_port": 443},
        {"name": "shop", "host": "10.0.0.2", "http_port": 80, "https_port": 443},
    ],
    "ssh": [
        {"name": "jump", "host": "10.0.0.3", "port": 22, "container": "jump-1"},
        {"name": "bastion", "host": "10.0.0.4", "port": 22},
    ],
    "documents": {**LAB["documents"], "dir": str(ROOT / "lab" / "profiles" / "hardened" / "org")},
}
PER_ASSET = {"portal": "weak", "jump": "weak", "shop": "hardened", "bastion": "hardened"}


def mixed_scan(tmp_path, per_asset=PER_ASSET, default="hardened"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / "target.yaml"
    path.write_text(yaml.safe_dump(MIXED))
    target = load_target(path)
    result = run_scan(
        target,
        load_profile(PROFILE),
        load_requirements(ROOT / "catalog" / "requirements"),
        now=collected_at(load_evidence("hardened", "tls_probe")),
        context=FixtureContext(target, default, per_asset),
    )
    return result, write_results(result, tmp_path / "out", PROFILE)


def by_key(findings):
    return {(f.check_id, f.asset): f for f in findings}


# --- target model ------------------------------------------------------------------


def test_single_mapping_and_default_names():
    target = Target.model_validate(
        {"name": "t", "web": {"host": "example.org", "http_port": 80, "https_port": 443}}
    )
    assert [w.name for w in target.web] == ["example.org:443"]
    assert target.assets("ssh") == [] and target.assets("documents") == []


def test_duplicate_asset_names_are_rejected():
    web = {"name": "www", "host": "a", "http_port": 80, "https_port": 443}
    with pytest.raises(ValidationError, match="duplicate web asset names: www"):
        Target.model_validate({"name": "t", "web": [web, {**web, "host": "b"}]})


# --- scanning ----------------------------------------------------------------------


def test_one_finding_per_check_and_asset(tmp_path):
    result, _ = mixed_scan(tmp_path)
    f = by_key(result.findings)
    assert f[("CHK-TLS-001", "portal")].status == CheckStatus.FAIL
    assert f[("CHK-TLS-001", "shop")].status == CheckStatus.PASS
    assert f[("CHK-SSH-001", "jump")].status == CheckStatus.FAIL
    assert f[("CHK-SSH-001", "bastion")].status == CheckStatus.PASS
    bastion_config = f[("CHK-SSH-002", "bastion")]
    assert bastion_config.status == CheckStatus.NOT_APPLICABLE
    assert bastion_config.message == "bastion has no container set"
    assert f[("CHK-DOC-001", "documents")].status == CheckStatus.PASS  # organisation-wide


def test_a_failure_on_any_asset_fails_the_requirement(tmp_path):
    result, _ = mixed_scan(tmp_path)
    crypto = next(v for v in result.verdicts if v.requirement_id == "REQ-NIS2-21.2.H")
    assert crypto.verdict == Verdict.NOT_SATISFIED
    assert crypto.reason.startswith("failed: CHK-TLS-001 on portal")


def test_evidence_is_written_per_asset(tmp_path):
    _, run_dir = mixed_scan(tmp_path)
    assert (run_dir / "evidence" / "tls_probe" / "portal.json").exists()
    assert (run_dir / "evidence" / "tls_probe" / "shop.json").exists()
    hashes = json.loads((run_dir / "scan.json").read_text())["evidence_sha256"]
    assert "tls_probe/portal" in hashes and "tls_probe/shop" in hashes


# --- report ------------------------------------------------------------------------


def test_report_groups_assets_per_check(tmp_path):
    _, run_dir = mixed_scan(tmp_path)
    data = load_run(run_dir)
    assert data.multi_asset
    tls = next(g for g in data.gaps if g.finding_id == "CHK-TLS-001")
    assert [a.asset for a in tls.assets] == ["portal", "shop"]
    assert [a.asset for a in tls.failing_assets] == ["portal"]
    assert tls.asset_kind == "web endpoints" and tls.evidence_sha256

    # Counted per check: TLS-001 fails once, even though it ran on two endpoints.
    assert data.check_counts["fail"] == len(data.gaps)
    assert len(data.findings) > len({f["check_id"] for f in data.findings})

    gap = next(g for g in data.narrative_input()["gaps"] if g["finding_id"] == "CHK-TLS-001")
    assert gap["assets_checked"] == 2
    assert [a["asset"] for a in gap["failing_assets"]] == ["portal"]

    html = render(data, run_dir)[0].read_text()
    assert "Fails on 1 of 2 web endpoints" in html and "Passes on shop." in html
    # The headline counts checks, not results: 16 checks ran on more assets than that.
    assert f"{data.check_counts['fail']} of 16 checks failed" in html
    assert "<th>Asset</th>" in html


def test_single_asset_report_has_no_asset_column(tmp_path):
    single = {**MIXED, "web": MIXED["web"][:1], "ssh": MIXED["ssh"][:1], "logs": LAB["logs"][:1]}
    path = tmp_path / "target.yaml"
    path.write_text(yaml.safe_dump(single))
    target = load_target(path)
    result = run_scan(
        target,
        load_profile(PROFILE),
        load_requirements(ROOT / "catalog" / "requirements"),
        now=collected_at(load_evidence("weak", "tls_probe")),
        context=FixtureContext(target, "weak"),
    )
    run = write_results(result, tmp_path / "out", PROFILE)
    html = render(load_run(run), run)[0].read_text()
    assert "<th>Asset</th>" not in html and "Fails on" not in html


# --- comparison --------------------------------------------------------------------


def test_diff_compares_per_asset(tmp_path):
    all_weak = {name: "weak" for name in PER_ASSET}
    _, before = mixed_scan(tmp_path / "before", all_weak, default="weak")
    _, after = mixed_scan(tmp_path / "after")
    c = compare(load_run(before), load_run(after))
    assert c.multi_asset
    fixed = {(ch.check_id, ch.asset) for ch in c.fixed}
    still_open = {(ch.check_id, ch.asset) for ch in c.still_open}
    assert ("CHK-TLS-001", "shop") in fixed
    assert ("CHK-TLS-001", "portal") in still_open
    assert ("CHK-SSH-001", "bastion") in fixed
    # bastion's config checks never apply, so they are neither fixed nor listed.
    listed = c.fixed + c.still_open + c.new + c.unresolved
    assert ("CHK-SSH-002", "bastion") not in {(ch.check_id, ch.asset) for ch in listed}


def test_runs_from_before_assets_still_compare(tmp_path):
    old = load_run(ROOT / "docs" / "example-report" / "weak")  # findings have no asset field
    new = load_run(scan_run(tmp_path, "hardened"))
    c = compare(old, new)
    # Checks with one result on each side pair up whatever the asset is called.
    assert len(c.fixed) == 15
    # The lab now has two log stores. The old run's one unnamed log store cannot be
    # matched to either, so log retention is listed as not comparable, not as fixed.
    assert {ch.check_id for ch in c.unresolved} == {"CHK-LOG-001"}
