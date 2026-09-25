"""The engagement: authorisation window, active tests, and what a scan records."""

import json
from datetime import UTC, datetime

import pytest
import yaml
from conftest import PROFILE, ROOT, FixtureContext, collected_at, load_evidence

from nis2scan.catalog import load_requirements
from nis2scan.config import load_profile, load_target
from nis2scan.models import CheckStatus
from nis2scan.report.data import load_run
from nis2scan.report.render import render
from nis2scan.scan import NotAuthorised, run_scan, write_results

LAB = yaml.safe_load((ROOT / "lab" / "target.yaml").read_text())
NOW = collected_at(load_evidence("weak", "tls_probe"))


def scan(tmp_path, engagement="lab", now=NOW):
    target = {
        **LAB,
        "documents": {**LAB["documents"], "dir": str(ROOT / "lab" / "profiles" / "weak" / "org")},
    }
    if engagement != "lab":
        target["engagement"] = engagement
    path = tmp_path / "target.yaml"
    path.write_text(yaml.safe_dump(target))
    t = load_target(path)
    return run_scan(
        t,
        load_profile(PROFILE),
        load_requirements(ROOT / "catalog" / "requirements"),
        now=now,
        context=FixtureContext(t, "weak"),
    )


def default_admin(result):
    return next(f for f in result.findings if f.check_id == "CHK-IDP-004")


def test_active_tests_run_when_authorised(tmp_path):
    assert default_admin(scan(tmp_path)).status == CheckStatus.FAIL


@pytest.mark.parametrize("active", [False, None])
def test_active_tests_are_skipped_unless_authorised(tmp_path, active):
    engagement = None if active is None else {**LAB["engagement"], "active_tests": active}
    finding = default_admin(scan(tmp_path, engagement))
    assert finding.status == CheckStatus.NOT_APPLICABLE
    assert "active test not authorised" in finding.message


def test_scans_outside_the_window_are_refused(tmp_path):
    with pytest.raises(NotAuthorised, match="authorises scans from 2026-09-01 to 2027-12-31"):
        scan(tmp_path, now=datetime(2028, 1, 1, tzinfo=UTC))


def test_engagement_is_recorded_and_reported(tmp_path):
    run = write_results(scan(tmp_path), tmp_path / "out", PROFILE)
    recorded = json.loads((run / "scan.json").read_text())["engagement"]
    assert recorded["client"] == "NordMSP AS (fictional lab)" and recorded["active_tests"]
    html = render(load_run(run), run)[0].read_text()
    assert "For <b>NordMSP AS (fictional lab)</b>" in html and "Active tests allowed" in html
