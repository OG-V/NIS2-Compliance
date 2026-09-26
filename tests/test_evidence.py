"""Document evidence: the reviewer decides, the tool verifies and records (ADR 0007)."""

import shutil
from datetime import date

import pytest
import yaml
from conftest import PROFILE, ROOT, FixtureContext, collected_at, load_evidence
from pydantic import ValidationError

from nis2scan.catalog import load_requirements
from nis2scan.collectors.evidence import evidence_register
from nis2scan.config import DocumentsTarget, Target, load_profile, load_target
from nis2scan.evidence import Review, apply, decide
from nis2scan.models import Verdict
from nis2scan.registry import Context, NotApplicable
from nis2scan.report.data import load_run
from nis2scan.report.render import render
from nis2scan.scan import run_scan, write_results

TODAY = date(2026, 9, 24)
ENTRY = {
    "requirement": "REQ-NIS2-21.2.G",
    "documents": ["training.md"],
    "verdict": "evidenced",
    "reviewed_by": "Ingrid Solberg, consultant",
    "reviewed_on": "2026-09-15",
    "rationale": "Every staff member completed the course in 2026.",
}


def reviewed(**changes) -> dict:
    """A register entry as the collector records it: documents with their hashes."""
    entry = {**ENTRY, **changes}
    docs = entry.pop("documents")
    hashes = entry.pop("hashes", ["ab" * 32] * len(docs))
    return entry | {
        "documents": [{"path": d, "sha256": h} for d, h in zip(docs, hashes, strict=True)]
    }


# --- the register format -----------------------------------------------------------


def test_an_evidenced_verdict_needs_a_document():
    with pytest.raises(ValidationError, match="needs at least one reviewed document"):
        Review.model_validate({**ENTRY, "documents": []})
    # Finding that a document is missing is a legitimate "not satisfied".
    Review.model_validate({**ENTRY, "documents": [], "verdict": "not_satisfied"})


@pytest.mark.parametrize("field", ["reviewed_by", "rationale"])
def test_a_review_names_its_reviewer_and_reasons(field):
    with pytest.raises(ValidationError):
        Review.model_validate({**ENTRY, field: ""})


def register_dir(tmp_path, entries, files=("training.md",)):
    tmp_path.mkdir(parents=True, exist_ok=True)
    for name in files:
        (tmp_path / name).write_text(f"contents of {name}\n")
    (tmp_path / "register.yaml").write_text(yaml.safe_dump({"reviews": entries}))
    return DocumentsTarget(
        dir=tmp_path, ir_plan="x", asset_inventory="y", evidence_register="register.yaml"
    )


def collect(docs):
    return evidence_register(Context(Target(name="t")), docs)


def test_documents_are_hashed_and_bad_entries_reported(tmp_path):
    docs = register_dir(
        tmp_path,
        [
            ENTRY,
            {**ENTRY, "requirement": "REQ-NIS2-21.2.D", "documents": ["gone.md"]},
            {"requirement": "REQ-NIS2-21.2.F"},
        ],
    )
    ev = collect(docs)
    hashes = {r["requirement"]: r["documents"][0]["sha256"] for r in ev["reviews"]}
    assert len(hashes["REQ-NIS2-21.2.G"]) == 64
    assert hashes["REQ-NIS2-21.2.D"] is None  # missing: recorded, judged later
    assert ev["problems"] == ["REQ-NIS2-21.2.F: Field required"]


def test_no_register_means_not_applicable(tmp_path):
    with pytest.raises(NotApplicable):
        collect(DocumentsTarget(dir=tmp_path, ir_plan="x", asset_inventory="y"))


# --- decisions -----------------------------------------------------------------------


def test_a_valid_review_carries_the_reviewers_verdict():
    d = decide(reviewed(), TODAY)
    assert d.verdict == Verdict.EVIDENCED
    assert d.reason.startswith("document review by Ingrid Solberg, consultant on 2026-09-15:")


@pytest.mark.parametrize(
    "changes, reason",
    [
        ({"hashes": [None]}, "reviewed document not found: training.md"),
        ({"reviewed_on": "2026-10-01"}, "review dated 2026-10-01, after the scan"),
        ({"valid_until": "2026-09-01"}, "document review expired on 2026-09-01"),
    ],
)
def test_reviews_that_cannot_be_relied_on_are_not_assessed(changes, reason):
    d = decide(reviewed(**changes), TODAY)
    assert (d.verdict, d.reason) == (Verdict.NOT_ASSESSED, reason)


def test_where_a_review_may_apply():
    register = {
        "reviews": [
            reviewed(),
            reviewed(requirement="REQ-UNKNOWN"),
            reviewed(requirement="REQ-NIS2-21.2.H"),  # covered by the TLS checks
            reviewed(requirement="REQ-NIS2-21.2.D"),
            reviewed(requirement="REQ-NIS2-21.2.D"),
        ]
    }
    known = {"REQ-NIS2-21.2.G", "REQ-NIS2-21.2.H", "REQ-NIS2-21.2.D"}
    decisions, problems = apply(register, known, {"REQ-NIS2-21.2.H"}, TODAY)
    assert list(decisions) == ["REQ-NIS2-21.2.G"]
    assert problems == [
        "REQ-UNKNOWN: not a requirement in the catalog",
        "REQ-NIS2-21.2.H: covered by automated checks, so a document review does not apply",
        "REQ-NIS2-21.2.D: reviewed more than once in the register; none applied",
    ]


# --- a scan with the lab's register ------------------------------------------------------

LAB = yaml.safe_load((ROOT / "lab" / "target.yaml").read_text())


def lab_scan(tmp_path, profile="hardened", register_changes=None, edit_org=None):
    org = tmp_path / "org"
    src = ROOT / "lab" / "profiles" / profile / "org"
    for f in src.rglob("*"):
        if f.is_file():
            (org / f.relative_to(src)).parent.mkdir(parents=True, exist_ok=True)
            (org / f.relative_to(src)).write_bytes(f.read_bytes())
    if edit_org:
        edit_org(org)
    if register_changes:
        register = yaml.safe_load((org / "evidence-register.yaml").read_text())
        register_changes(register["reviews"])
        (org / "evidence-register.yaml").write_text(yaml.safe_dump(register))
    target = {**LAB, "documents": {**LAB["documents"], "dir": str(org)}}
    (tmp_path / "target.yaml").write_text(yaml.safe_dump(target))
    t = load_target(tmp_path / "target.yaml")

    class Live(FixtureContext):  # recorded evidence, but the real register from disk
        def _run(self, name, asset):
            if name == "evidence_register":
                return Context._run(self, name, asset)
            return super()._run(name, asset)

    result = run_scan(
        t,
        load_profile(PROFILE),
        load_requirements(ROOT / "catalog" / "requirements"),
        now=collected_at(load_evidence(profile, "tls_probe")),
        context=Live(t, profile),
    )
    return result, write_results(result, tmp_path / "out", PROFILE)


def verdict_of(result, req):
    return next(v for v in result.verdicts if v.requirement_id == req)


def test_an_expired_review_is_shown_but_not_counted(tmp_path):
    def expire(reviews):
        next(r for r in reviews if r["requirement"] == "REQ-NIS2-21.2.G")["valid_until"] = (
            "2026-01-01"
        )

    result, _ = lab_scan(tmp_path, register_changes=expire)
    training = verdict_of(result, "REQ-NIS2-21.2.G")
    assert (training.basis, training.verdict) == ("document", Verdict.NOT_ASSESSED)
    assert training.reason == "document review expired on 2026-01-01"


def test_a_changed_document_changes_its_recorded_hash(tmp_path):
    original, _ = lab_scan(tmp_path / "a")
    edited, _ = lab_scan(
        tmp_path / "b",
        edit_org=lambda org: (org / "evidence" / "backup-plan.md").write_text(
            "edited after review"
        ),
    )
    before = verdict_of(original, "REQ-CIR2690-4.2.2-01").document_review["documents"][0]
    after = verdict_of(edited, "REQ-CIR2690-4.2.2-01").document_review["documents"][0]
    assert before["path"] == after["path"] and before["sha256"] != after["sha256"]


def test_report_shows_the_reviews(tmp_path):
    _, run = lab_scan(tmp_path, profile="weak")
    data = load_run(run)
    assert [r["verdict"] for r in data.reviews] == ["not_satisfied"] * 4
    assert data.document_review["applied"] == 4 and data.document_review["problems"] == []
    html = render(data, run)[0].read_text()
    assert "Document review (4)" in html
    assert "none: the reviewer found no document to review" in html  # no backup plan exists
    assert "The policy has not been reviewed since it was written in February 2023." in html


def test_runs_without_reviews_render_as_before(tmp_path):
    run = tmp_path / "legacy-run"
    shutil.copytree(ROOT / "tests" / "fixtures" / "legacy-run", run)
    data = load_run(run)
    assert data.reviews == [] and data.document_review is None
    html = render(data, run)[0].read_text()
    assert "Document review" not in html and "by document review" not in html


# --- helping the reviewer -------------------------------------------------------------


def test_template_lists_every_unchecked_requirement_and_parses():
    from nis2scan.evidence import template
    from nis2scan.registry import CHECKS

    reqs = load_requirements(ROOT / "catalog" / "requirements")
    checked = {r for c in CHECKS.values() for r in c.meta.requirements}
    text = template(reqs, checked)
    assert yaml.safe_load(text) == {"reviews": None}  # valid, and empty until filled in
    listed = {
        line.split(": ")[1] for line in text.splitlines() if line.startswith("# - requirement:")
    }
    assert listed == {r.id for r in reqs} - checked
    # Uncommenting one entry and filling it in gives a valid review.
    entry = text.split("# - requirement: REQ-NIS2-21.2.G\n")[1].split("# - requirement")[0]
    # Uncommenting removes the leading "# " from each line of the entry.
    filled = "reviews:\n- requirement: REQ-NIS2-21.2.G\n" + "\n".join(
        line[2:] for line in entry.splitlines() if line.startswith("#   ")
    )
    raw = yaml.safe_load(filled)["reviews"][0] | {
        "verdict": "not_satisfied",
        "reviewed_by": "X",
        "reviewed_on": "2026-09-15",
        "rationale": "No records.",
    }
    Review.model_validate(raw)


def test_onboarding_reports_the_register(tmp_path):
    from nis2scan.onboarding import MISSING, OK, _evidence_register

    good = register_dir(tmp_path / "good", [ENTRY])
    assert _evidence_register(good).status == OK
    bad = register_dir(tmp_path / "bad", [{**ENTRY, "documents": ["gone.md"]}])
    access = _evidence_register(bad)
    assert access.status == MISSING and "document not found: gone.md" in access.note
