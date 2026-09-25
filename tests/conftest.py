import json
from datetime import datetime
from pathlib import Path

import pytest

from nis2scan.config import slug
from nis2scan.registry import Context, load_all

ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "evidence"
PROFILES = ["weak", "hardened"]

load_all()


def load_evidence(profile: str, collector: str, asset: str | None = None) -> dict:
    """Recorded evidence; <collector>/<asset>.json when a collector has one per asset."""
    per_asset = FIXTURES / profile / collector / f"{slug(asset)}.json" if asset else None
    path = (
        per_asset if per_asset and per_asset.exists() else FIXTURES / profile / f"{collector}.json"
    )
    return json.loads(path.read_text())


def recorded(profile: str, collector: str) -> dict[str | None, dict]:
    """Every recorded asset's evidence for a collector: {asset: evidence}, or {None: ...}."""
    folder = FIXTURES / profile / collector
    if folder.is_dir():
        return {p.stem: json.loads(p.read_text()) for p in sorted(folder.glob("*.json"))}
    return {None: load_evidence(profile, collector)}


def collected_at(evidence: dict) -> datetime:
    return datetime.fromisoformat(evidence["_collected_at"])


class FixtureContext(Context):
    """Serves evidence recorded from a real lab run instead of probing a live target.

    `per_asset` maps asset names to a lab profile, so one target can mix assets
    recorded from the weak and the hardened lab.
    """

    def __init__(self, target, profile: str, per_asset: dict[str, str] | None = None):
        super().__init__(target)
        self.profile = profile
        self.per_asset = per_asset or {}

    def _run(self, name: str, asset) -> dict:
        return load_evidence(self.per_asset.get(asset.name, self.profile), name, asset.name)


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
