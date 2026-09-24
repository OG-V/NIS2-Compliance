"""Every check against evidence recorded from both lab profiles (the lab README's answer key)."""

from datetime import timedelta

import pytest
from conftest import PROFILES, ROOT, collected_at, load_evidence

from nis2scan.checks.identity import min_password_length
from nis2scan.checks.operations import parse_duration
from nis2scan.collectors.ssh import parse_sshd_t
from nis2scan.config import load_profile
from nis2scan.models import CheckStatus
from nis2scan.registry import CHECKS

PROFILE = load_profile(ROOT / "catalog" / "profile.yaml")
EXPECTED = {"weak": CheckStatus.FAIL, "hardened": CheckStatus.PASS}


@pytest.mark.parametrize("lab_profile", PROFILES)
@pytest.mark.parametrize("check_id", sorted(CHECKS))
def test_check_matches_answer_key(check_id, lab_profile):
    chk = CHECKS[check_id]
    evidence = load_evidence(lab_profile, chk.collector)
    # Evaluate at collection time so date-based checks don't drift as fixtures age.
    result = chk.evaluate(evidence, PROFILE, collected_at(evidence))
    assert result.status == EXPECTED[lab_profile], result.message


def test_risk_exceptions_lapse_after_expiry():
    chk = CHECKS["CHK-VUL-001"]
    evidence = load_evidence("hardened", chk.collector)
    expiry = max(e["expires"] for e in evidence["risk_exceptions"])
    later = collected_at(evidence).replace(
        year=int(expiry[:4]), month=int(expiry[5:7]), day=int(expiry[8:10])
    ) + timedelta(days=1)

    result = chk.evaluate(evidence, PROFILE, later)

    assert result.status == CheckStatus.FAIL
    assert result.observed["expired_exceptions"]
    assert result.observed["accepted_risks"] == []


def test_ir_plan_review_goes_stale():
    chk = CHECKS["CHK-DOC-002"]
    evidence = load_evidence("hardened", chk.collector)
    much_later = collected_at(evidence) + timedelta(
        days=PROFILE.incident_response.max_review_age_days
    )
    assert chk.evaluate(evidence, PROFILE, much_later).status == CheckStatus.FAIL


@pytest.mark.parametrize(
    "text, expected",
    [
        ("1w", timedelta(weeks=1)),
        ("180d", timedelta(days=180)),
        ("4320h", timedelta(hours=4320)),
        ("1d12h", timedelta(days=1, hours=12)),
        ("0s", timedelta(0)),
    ],
)
def test_parse_duration(text, expected):
    assert parse_duration(text) == expected


@pytest.mark.parametrize("text", ["", "7", "7 days", "1x", "1d junk"])
def test_parse_duration_rejects_garbage(text):
    with pytest.raises(ValueError):
        parse_duration(text)


@pytest.mark.parametrize(
    "policy, expected",
    [
        ("length(12) and notUsername", 12),
        ("notUsername and length(8)", 8),
        ("maxLength(64)", 0),
        ("", 0),
        (None, 0),
    ],
)
def test_min_password_length(policy, expected):
    assert min_password_length(policy) == expected


def test_parse_sshd_t_collects_repeated_keys():
    config = parse_sshd_t("port 22\nhostkey /a\nhostkey /b\npermitrootlogin no\n")
    assert config == {"port": "22", "hostkey": ["/a", "/b"], "permitrootlogin": "no"}
