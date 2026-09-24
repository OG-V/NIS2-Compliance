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
