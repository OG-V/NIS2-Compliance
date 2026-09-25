import json
from datetime import datetime
from pathlib import Path

import pytest

from nis2scan.registry import Context, load_all

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "evidence"
PROFILES = ["weak", "hardened"]

load_all()


def load_evidence(profile: str, collector: str) -> dict:
    return json.loads((FIXTURES / profile / f"{collector}.json").read_text())


def collected_at(evidence: dict) -> datetime:
    return datetime.fromisoformat(evidence["_collected_at"])


class FixtureContext(Context):
    """Serves evidence recorded from a real lab run instead of probing a live target."""

    def __init__(self, target, profile: str):
        super().__init__(target)
        self.profile = profile

    def _run(self, name: str) -> dict:
        return load_evidence(self.profile, name)


@pytest.fixture
def root() -> Path:
    return ROOT


PROFILE = ROOT / "catalog" / "profile.yaml"


def scan_run(tmp_path: Path, lab_profile: str) -> Path:
    """Scan the recorded evidence of a lab profile and write a result directory."""
    from nis2scan.catalog import load_requirements
    from nis2scan.config import load_profile, load_target
    from nis2scan.scan import run_scan, write_results

    target = load_target(ROOT / "lab" / "target.yaml")
    result = run_scan(
        target,
        load_profile(PROFILE),
        load_requirements(ROOT / "catalog" / "requirements"),
        now=collected_at(load_evidence(lab_profile, "tls_probe")),
        context=FixtureContext(target, lab_profile),
    )
    return write_results(result, tmp_path / lab_profile, PROFILE)
