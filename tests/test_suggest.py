"""Evidence suggestions: the model points to passages, code verifies, a person decides."""

import json
import zipfile
from types import SimpleNamespace

import pytest
import yaml
from conftest import ROOT
from typer.testing import CliRunner

from nis2scan.catalog import load_requirements
from nis2scan.doctext import UnreadableDocument, extract_text
from nis2scan.evidence import Review
from nis2scan.registry import CHECKS, load_all
from nis2scan.suggest import (
    GoldSuggestions,
    Suggestion,
    Suggestions,
    catalog_block,
    chunks,
    draft_entries,
    score,
    suggest,
    verify,
)

load_all()
CHECKED = {r for c in CHECKS.values() for r in c.meta.requirements}
UNCHECKED = [r for r in load_requirements(ROOT / "catalog" / "requirements") if r.id not in CHECKED]
BACKUP_PLAN = ROOT / "lab" / "profiles" / "hardened" / "org" / "evidence" / "backup-plan.md"
TEXT = BACKUP_PLAN.read_text()
EXCERPT = "Restores are tested quarterly; the last restore test was 2026-07-02"


class FakeClient:
    def __init__(self, outputs, stop_reason="end_turn"):
        self.outputs = list(outputs)
        self.calls = []
        self.stop_reason = stop_reason
        self.beta = SimpleNamespace(messages=SimpleNamespace(parse=self._parse))

    def _parse(self, **kwargs):
        self.calls.append(kwargs)
        usage = SimpleNamespace(input_tokens=100, output_tokens=50, cache_read_input_tokens=9000)
        return SimpleNamespace(
            stop_reason=self.stop_reason,
            parsed_output=self.outputs.pop(0),
            model="claude-opus-5-5",
            usage=usage,
        )


def s(req, *excerpts, addresses="Restore testing."):
    return Suggestion(requirement_id=req, excerpts=list(excerpts or [EXCERPT]), addresses=addresses)


# --- reading documents ------------------------------------------------------------------


def test_reads_text_and_word(tmp_path):
    assert "Backup and Recovery Plan" in extract_text(BACKUP_PLAN)
    docx = tmp_path / "policy.docx"
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    body = "".join(
        f"<w:p><w:r><w:t>{t}</w:t></w:r></w:p>" for t in ("Access policy", "Reviewed yearly.")
    )
    with zipfile.ZipFile(docx, "w") as z:
        z.writestr(
            "word/document.xml", f'<w:document xmlns:w="{ns}"><w:body>{body}</w:body></w:document>'
        )
    assert extract_text(docx) == "Access policy\nReviewed yearly."


@pytest.mark.parametrize(
    "name, content, message",
    [
        ("scan.xlsx", b"x", "unsupported format .xlsx"),
        ("empty.md", b"  \n", "no text"),
        ("broken.docx", b"not a zip", "not a readable Word document"),
    ],
)
def test_unreadable_documents_are_reported(tmp_path, name, content, message):
    (tmp_path / name).write_bytes(content)
    with pytest.raises(UnreadableDocument, match=message):
        extract_text(tmp_path / name)


def test_reads_pdf(tmp_path):
    pypdf = pytest.importorskip("pypdf")
    empty = tmp_path / "scanned.pdf"
    writer = pypdf.PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.write(empty)
    with pytest.raises(UnreadableDocument, match="OCR"):
        extract_text(empty)


# --- verification -----------------------------------------------------------------------


def test_only_verified_suggestions_are_accepted():
    allowed = {r.id for r in UNCHECKED}
    accepted, rejected = verify(
        [
            s("REQ-CIR2690-4.2.3-01"),
            s("REQ-NIS2-21.2.H"),  # covered by the TLS checks
            s("REQ-MADE-UP"),
            s("REQ-CIR2690-4.2.2-06", "Restores are tested every week without fail."),
            s("REQ-CIR2690-4.2.2-01", "Backup and Recovery Plan"),  # the title
            s("REQ-CIR2690-4.2.2-02", "Recovery time"),
            # whitespace and typographic differences are tolerated
            s(
                "REQ-CIR2690-4.2.2-04",
                "Backups are  encrypted and kept off the production network.",
            ),
        ],
        TEXT,
        allowed,
    )
    assert [a["requirement_id"] for a in accepted] == [
        "REQ-CIR2690-4.2.3-01",
        "REQ-CIR2690-4.2.2-04",
    ]
    assert [r["reason"] for r in rejected] == [
        "not an unchecked requirement in the catalog",
        "not an unchecked requirement in the catalog",
        "excerpt is not verbatim in the document",
        "excerpt is a title or heading, not content",
        "excerpt too short to show anything",
    ]


def test_short_sentences_and_table_rows_are_content():
    policy = "# IT security rules\n\nVersion 1.0\n\n- Use strong passwords.\n- Lock your screen\n"
    table = "| Service | Backup |\n|---|---|\n| Customer portal | nightly, restic |\n"
    ok = [
        ("Use strong passwords.", policy),
        ("Lock your screen", policy),  # a list item, not a heading
        ("Customer portal | nightly, restic", table),
    ]
    for excerpt, text in ok:
        accepted, rejected = verify([s("REQ-NIS2-21.2.G", excerpt)], text, {"REQ-NIS2-21.2.G"})
        assert accepted and not rejected, (excerpt, rejected)
    for excerpt in ("IT security rules", "Version 1.0"):
        _, rejected = verify([s("REQ-NIS2-21.2.G", excerpt)], policy, {"REQ-NIS2-21.2.G"})
        assert rejected[0]["reason"] in (
            "excerpt is a title or heading, not content",
            "excerpt too short to show anything",
        ), excerpt


def test_several_excerpts_are_kept_and_repeats_merged():
    second = "Backups are encrypted and kept off the production network."
    accepted, rejected = verify(
        [
            s("REQ-CIR2690-4.2.3-01", EXCERPT, "Restores are tested daily by robots."),
            s("REQ-CIR2690-4.2.3-01", second, EXCERPT),  # e.g. from a second chunk
        ],
        TEXT,
        {"REQ-CIR2690-4.2.3-01"},
    )
    assert len(accepted) == 1 and accepted[0]["excerpts"] == [EXCERPT, second]
    assert [r["excerpt"] for r in rejected] == ["Restores are tested daily by robots."]


def test_suggest_sends_the_catalog_as_a_cached_block_and_records_usage():
    client = FakeClient([Suggestions(suggestions=[s("REQ-CIR2690-4.2.3-01")])])
    result = suggest(client, "backup-plan.md", TEXT, UNCHECKED)
    system = client.calls[0]["system"]
    assert system[1]["cache_control"] == {"type": "ephemeral"}
    assert "REQ-CIR2690-4.2.3-01 | Regular backup integrity checks" in system[1]["text"]
    assert "REQ-NIS2-21.2.H" not in system[1]["text"]  # checked requirements are not offered
    assert "<document>" in client.calls[0]["messages"][0]["content"]
    assert [a["requirement_id"] for a in result.accepted] == ["REQ-CIR2690-4.2.3-01"]
    assert result.usage[0]["cache_read_input_tokens"] == 9000


def test_catalog_block_is_stable_for_caching():
    assert catalog_block(UNCHECKED) == catalog_block(list(reversed(UNCHECKED)))


def test_a_refusal_is_an_error_not_an_empty_result():
    result = suggest(FakeClient([None], stop_reason="refusal"), "d.md", TEXT, UNCHECKED)
    assert result.error == "model stopped with refusal" and result.accepted == []


def test_long_documents_are_split_and_verified_as_a_whole():
    paragraphs = [f"Paragraph {i}. " + "word " * 50 for i in range(30)]
    text = "\n\n".join(paragraphs)
    parts = chunks(text, limit=1000)
    assert len(parts) > 1 and all(len(p) <= 1000 for p in parts)
    assert "\n\n".join(parts) == text
    first = Suggestions(suggestions=[s("REQ-NIS2-21.2.G", paragraphs[0].strip())])
    rest = [Suggestions(suggestions=[]) for _ in parts[1:]]
    client = FakeClient([first, *rest])
    result = suggest(client, "d.md", text, UNCHECKED, max_chars=1000)
    assert len(client.calls) == len(parts)
    assert [a["requirement_id"] for a in result.accepted] == ["REQ-NIS2-21.2.G"]


# --- draft register entries -------------------------------------------------------------


def test_drafts_are_commented_and_need_a_reviewer():
    result = suggest(
        FakeClient(
            [
                Suggestions(
                    suggestions=[
                        s(
                            "REQ-CIR2690-4.2.3-01",
                            EXCERPT,
                            "Backups are encrypted and kept off the production network.",
                            addresses='The "quarterly" restore tests.',
                        )
                    ]
                )
            ]
        ),
        "backup-plan.md",
        TEXT,
        UNCHECKED,
    )
    text = draft_entries(result, "evidence/backup-plan.md", {r.id: r.title for r in UNCHECKED})
    assert "by claude-opus-5-5" in text and "Not reviewed" in text
    assert text.count("#   # Excerpt: ") == 2
    assert yaml.safe_load("reviews:\n" + text) == {"reviews": None}  # all commented out
    # Uncommented as it stands, the entry is refused: the verdict is the reviewer's.
    entry = "\n".join(line[2:] for line in text.splitlines() if line.startswith(("# -", "#   ")))
    raw = yaml.safe_load(entry)[0]
    assert raw["documents"] == ["evidence/backup-plan.md"] and raw["verdict"] is None
    with pytest.raises(ValueError):
        Review.model_validate(raw)


# --- evaluation -------------------------------------------------------------------------


def test_scoring_against_the_gold_set():
    gold = GoldSuggestions.model_validate(
        {
            "labelled_by": "test",
            "status": "draft",
            "documents": {
                "a.md": {"must": ["R1", "R2"], "may": ["R3"]},
                "b.md": {"must": [], "may": []},
                "c.md": {"must": ["R4"]},
            },
        }
    )
    results = [
        {
            "document": "a.md",
            "accepted": [{"requirement_id": r} for r in ("R1", "R3", "R9")],
            "rejected": [{}],
        },
        {"document": "b.md", "accepted": [{"requirement_id": "R5"}], "rejected": []},
    ]
    scores, totals = score(results, gold)
    assert (scores[0].hits, scores[0].missed, scores[0].false_positives) == (["R1"], ["R2"], ["R9"])
    assert totals["precision"] == 0.5  # R1, R3 of R1, R3, R9, R5
    assert totals["recall"] == 0.333  # R1 of R1, R2, R4
    assert totals["rejected_by_verification"] == 1
    assert totals["documents_without_result"] == ["c.md"]


def test_gold_set_documents_exist_and_labels_are_unchecked_requirements():
    gold = GoldSuggestions.model_validate(
        yaml.safe_load((ROOT / "eval" / "gold-suggestions.yaml").read_text())
    )
    ids = {r.id for r in UNCHECKED}
    for doc, labels in gold.documents.items():
        assert (ROOT / doc).is_file(), doc
        assert set(labels.must) | set(labels.may) <= ids, doc
        assert not set(labels.must) & set(labels.may), doc


def test_evaluate_suggestions_command(tmp_path):
    from nis2scan.cli import app

    (tmp_path / "run").mkdir()
    (tmp_path / "run" / "x.json").write_text(
        json.dumps(
            {
                "document": "lab/profiles/hardened/org/evidence/supplier-register.md",
                "accepted": [{"requirement_id": "REQ-NIS2-21.2.D"}],
                "rejected": [],
            }
        )
    )
    out = CliRunner().invoke(
        app,
        [
            "evaluate-suggestions",
            str(tmp_path / "run"),
            "--gold",
            str(ROOT / "eval" / "gold-suggestions.yaml"),
        ],
    )
    assert out.exit_code == 0, out.output
    assert "precision                  1.0" in out.output
