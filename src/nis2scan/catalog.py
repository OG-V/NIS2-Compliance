"""Loading the requirement catalog."""

from pathlib import Path

import yaml

from nis2scan.models import Requirement, ReviewStatus


def load_requirements(path: Path, include_drafts: bool = False) -> list[Requirement]:
    """Load reviewed requirements (and drafts, if asked). Rejected ones are never loaded."""
    requirements = []
    for req in load_all_requirements(path):
        if req.review.status == ReviewStatus.REVIEWED or (
            include_drafts and req.review.status == ReviewStatus.DRAFT
        ):
            requirements.append(req)
    return requirements


def load_all_requirements(path: Path) -> list[Requirement]:
    """Every requirement under path, in any review state, including subdirectories."""
    return [
        Requirement.model_validate(yaml.safe_load(file.read_text()))
        for file in sorted(path.rglob("*.yaml"))
    ]
