"""Integrity of the requirement catalog and the check registry."""

import ast
from pathlib import Path

from conftest import ROOT

from nis2scan.catalog import load_requirements
from nis2scan.extract.sources import NIS2
from nis2scan.models import ReviewStatus
from nis2scan.registry import CHECKS, COLLECTORS

REQS = load_requirements(ROOT / "catalog" / "requirements", include_drafts=True)
REQ_IDS = {r.id for r in REQS}


def test_requirement_ids_unique():
    assert len(REQ_IDS) == len(REQS)


def test_checks_reference_existing_requirements_and_collectors():
    for chk in CHECKS.values():
        assert set(chk.meta.requirements) <= REQ_IDS, chk.meta.id
        assert chk.collector in COLLECTORS, chk.meta.id


def test_every_technical_nis2_requirement_has_a_check():
    covered = {r for c in CHECKS.values() for r in c.meta.requirements}
    for req in REQS:
        if req.source.instrument == NIS2.instrument and req.testability != "organisational":
            assert req.id in covered, req.id


def test_drafts_excluded_by_default():
    reviewed = load_requirements(ROOT / "catalog" / "requirements")
    assert all(r.review.status == ReviewStatus.REVIEWED for r in reviewed)


def test_checks_never_import_an_llm_client():
    """ADR 0001: verdicts are deterministic. Enforced, not just documented."""
    forbidden = {"anthropic", "openai", "nis2scan.extract", "nis2scan.report"}
    for path in (ROOT / "src" / "nis2scan" / "checks").glob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                assert not any(name == f or name.startswith(f + ".") for f in forbidden), (
                    f"{Path(path).name} imports {name}"
                )


def test_mapping_document_is_up_to_date():
    """docs/check-mapping.md is what reviewers read; it must match the code."""
    from nis2scan.mapping import render_markdown

    committed = (ROOT / "docs" / "check-mapping.md").read_text()
    assert committed == render_markdown(ROOT / "catalog" / "requirements"), (
        "regenerate with: nis2scan checks --markdown > docs/check-mapping.md"
    )
