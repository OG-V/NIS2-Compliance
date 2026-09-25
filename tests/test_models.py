from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from nis2scan.models import CheckMeta, CheckStatus, Finding, Requirement, Verdict, rollup

CATALOG = Path(__file__).parent.parent / "catalog" / "requirements"


@pytest.mark.parametrize("file", sorted(CATALOG.rglob("*.yaml")), ids=lambda p: p.name)
def test_catalog_files_validate(file):
    Requirement.model_validate(yaml.safe_load(file.read_text()))


def check(id_, coverage="full"):
    return CheckMeta(
        id=id_,
        title=id_,
        requirements=["REQ-X"],
        coverage=coverage,
        severity="high",
        severity_rationale="test",
        action="test",
        effort="quick",
        target_type="test",
    )


def finding(check_id, status):
    return Finding(
        check_id=check_id,
        target="t",
        status=status,
        collected_at=datetime.now(UTC),
    )


@pytest.mark.parametrize(
    "checks, statuses, expected",
    [
        ([], [], Verdict.NOT_ASSESSED),
        ([check("CHK-A")], ["pass"], Verdict.EVIDENCED),
        ([check("CHK-A", "partial")], ["pass"], Verdict.PARTIALLY_EVIDENCED),
        ([check("CHK-A"), check("CHK-B")], ["pass", "fail"], Verdict.NOT_SATISFIED),
        ([check("CHK-A"), check("CHK-B")], ["pass", "error"], Verdict.NOT_ASSESSED),
        ([check("CHK-A"), check("CHK-B")], ["error", "fail"], Verdict.NOT_SATISFIED),
        ([check("CHK-A")], ["not_applicable"], Verdict.NOT_ASSESSED),
    ],
)
def test_rollup(checks, statuses, expected):
    findings = [finding(c.id, CheckStatus(s)) for c, s in zip(checks, statuses)]
    assert rollup(checks, findings) == expected
