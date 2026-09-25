"""Scan the running lab. Opt-in: NIS2_LAB=1 pytest tests/test_lab_live.py (takes ~1-2 min)."""

import os

import pytest
from conftest import ROOT

from nis2scan.catalog import load_requirements
from nis2scan.config import load_profile, load_target
from nis2scan.models import CheckStatus
from nis2scan.scan import run_scan

pytestmark = pytest.mark.skipif(not os.environ.get("NIS2_LAB"), reason="set NIS2_LAB=1 to run")


def test_live_scan_matches_running_profile():
    current = ROOT / "lab" / ".current"
    if not current.exists():
        pytest.skip("no lab profile is running (./lab/lab.sh up <profile>)")
    lab_profile = current.resolve().name
    expected = {"weak": CheckStatus.FAIL, "hardened": CheckStatus.PASS}[lab_profile]

    result = run_scan(
        load_target(ROOT / "lab" / "target.yaml"),
        load_profile(ROOT / "catalog" / "profile.yaml"),
        load_requirements(ROOT / "catalog" / "requirements"),
    )

    by_check: dict[str, list] = {}
    for f in result.findings:
        by_check.setdefault(f.check_id, []).append(f)
    if lab_profile == "hardened":
        wrong = {(f.check_id, f.asset): f.message for f in result.findings if f.status != expected}
    else:
        # Every check fails on the weak lab, though not on every asset: its restic
        # repository is encrypted, as restic always is.
        wrong = {
            c: [f.message for f in fs]
            for c, fs in by_check.items()
            if not any(f.status == expected for f in fs)
        }
    assert not wrong, f"{lab_profile}: {wrong}"
