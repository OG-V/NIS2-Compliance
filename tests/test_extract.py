"""Source parsing, quote verification, extraction (with a fake client) and evaluation."""

import json
import re
from dataclasses import replace
from types import SimpleNamespace

import pytest
import yaml
from conftest import ROOT

from nis2scan.catalog import load_requirements
from nis2scan.extract import llm
from nis2scan.extract.evaluate import evaluate, invented_terms, load_gold
from nis2scan.extract.sources import CIR_2690, NIS2, article_text, parse_annex, read_text, sha256
from nis2scan.extract.verify import QuoteStatus, SourceIndex, check_quote, contains
from nis2scan.models import ReviewStatus

SOURCES = ROOT / "sources"
INDEX = SourceIndex(SOURCES)
ANNEX_TEXT = read_text(CIR_2690, SOURCES)
PROVISIONS = {p.number: p for p in parse_annex(ANNEX_TEXT)}


# --- sources -----------------------------------------------------------------


def test_stored_sources_match_manifest():
    manifest = json.loads((SOURCES / "manifest.json").read_text())
    for entry in manifest.values():
        assert sha256(SOURCES / entry["file"]) == entry["sha256"], entry["file"]


def test_annex_parses_every_numbered_point():
    numbers = re.findall(r"^(\d+(?:\.\d+)*)\. ", ANNEX_TEXT, flags=re.MULTILINE)
    sections = [n for n in numbers if "." not in n]
    headings = [n for n in numbers if n.count(".") == 1 and n not in PROVISIONS]
    assert len(sections) == 13
    assert len(PROVISIONS) == 159
    assert len(numbers) == len(sections) + len(headings) + len(PROVISIONS)


def test_sections_without_subsections_are_provisions():
    assert {"7.1", "7.2", "7.3", "9.1", "9.2", "9.3"} <= set(PROVISIONS)
    assert PROVISIONS["9.2"].nis2_article == "21(2)(h)"
    assert "(xii) setting activation and deactivation dates" in PROVISIONS["9.2"].text


def test_provision_traces_to_nis2():
    mfa = PROVISIONS["11.7.1"]
    assert mfa.nis2_points == ("i", "j")
    assert mfa.subsection == "11.7. Multi-factor authentication"
    assert all(p.nis2_points for p in PROVISIONS.values())


def test_article_text_is_bounded():
    art21 = article_text(read_text(NIS2, SOURCES), 21)
    assert art21.startswith("Article 21")
    assert "multi-factor authentication" in art21
    assert "Article 22" not in art21.splitlines()  # stops before the next article heading
    assert "Article 22(1)" in art21  # cross-references inside the article are kept


# --- quote verification -------------------------------------------------------


def test_reviewed_catalog_quotes_are_verbatim():
    """Regression guard for the human review: every reviewed quote is in the cited article."""
    for req in load_requirements(ROOT / "catalog" / "requirements"):
        assert check_quote(req, INDEX).status == QuoteStatus.VERBATIM, req.id


def _nis2_req(provision: str, quote: str):
    req = next(
        r
        for r in load_requirements(ROOT / "catalog" / "requirements")
        if r.source.instrument == NIS2.instrument
    )
    source = req.source.model_copy(update={"provision": provision, "quote": quote})
    return req.model_copy(update={"source": source})


def test_altered_quote_is_not_found():
    req = _nis2_req("Art. 21(2)(j)", "the mandatory use of multi-factor authentication")
    assert check_quote(req, INDEX).status == QuoteStatus.NOT_FOUND


def test_quote_from_another_article_is_flagged():
    quote = "within 24 hours of becoming aware of the significant incident"  # Art. 23
    assert check_quote(_nis2_req("Art. 21(2)(b)", quote), INDEX).status == QuoteStatus.ELSEWHERE


def test_unknown_provision_is_unlocatable():
    req = _nis2_req("Annex, point 99.9.9", "anything")
    req = req.model_copy(
        update={"source": req.source.model_copy(update={"instrument": CIR_2690.instrument})}
    )
    assert check_quote(req, INDEX).status == QuoteStatus.UNLOCATABLE


def test_matching_ignores_typography_and_whitespace_only():
    text = "the relevant entities’ network\nand information systems"
    assert contains(text, "the relevant entities' network and  information systems")
    assert not contains(text, "The relevant entities' network")  # case still matters
    assert not contains(text, "")


# --- extraction ---------------------------------------------------------------


def _item(quote, **overrides):
    fields = {
        "title": "MFA for users",
        "obligation": "The entity shall authenticate users with multiple factors where appropriate.",
        "quote": quote,
        "testability": "technical",
        "evidence": ["identity provider MFA policy"],
        "parameters": [],
    }
    return llm.ExtractedRequirement(**(fields | overrides))


MFA_QUOTE = "users are authenticated by multiple authentication factors"


class FakeClient:
    """Stands in for anthropic.Anthropic(): records the request, returns a canned result."""

    def __init__(self, result=None, stop_reason="end_turn"):
        self.calls = []
        self.result = result
        self.stop_reason = stop_reason
        self.beta = SimpleNamespace(messages=SimpleNamespace(parse=self._parse))

    def _parse(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(
            stop_reason=self.stop_reason, parsed_output=self.result, model="claude-opus-5"
        )


def test_request_shape():
    client = FakeClient(llm.ExtractionResult(requirements=[_item(MFA_QUOTE)]))
    llm.call_model(client, PROVISIONS["11.7.1"])
    call = client.calls[0]
    assert call["model"] == llm.MODEL
    assert call["output_format"] is llm.ExtractionResult
    assert call["fallbacks"] == "default" and call["betas"] == [llm.FALLBACK_BETA]
    assert "<provision>\nThe relevant entities shall ensure" in call["messages"][0]["content"]


def test_valid_extraction_becomes_traceable_draft():
    result = llm.ExtractionResult(
        requirements=[
            _item(
                MFA_QUOTE,
                parameters=[
                    llm.Parameter(name="asset_scope", stated_value=None),
                    llm.Parameter(name="qualifier", stated_value="where appropriate"),
                ],
            )
        ]
    )
    [req] = llm.to_requirements(PROVISIONS["11.7.1"], result, "claude-opus-5", "abc", INDEX)
    assert req.id == "REQ-CIR2690-11.7.1-01"
    assert req.source.provision == "Annex, point 11.7.1"
    assert req.source.nis2_article == "21(2)(i), (j)"
    assert req.parameters == {"asset_scope": "entity_defined", "qualifier": "where appropriate"}
    assert req.extraction.prompt_version == llm.PROMPT_VERSION
    assert req.review.status == ReviewStatus.DRAFT


def test_paraphrased_quote_is_rejected():
    result = llm.ExtractionResult(requirements=[_item("users must use MFA")])
    [req] = llm.to_requirements(PROVISIONS["11.7.1"], result, "m", "abc", INDEX)
    assert req.review.status == ReviewStatus.REJECTED
    assert "quote not_found" in req.review.notes


def test_invented_parameter_value_is_rejected():
    item = _item(
        "require the reset of authentication credentials and the blocking of users",
        parameters=[llm.Parameter(name="max_failed_logins", stated_value="5 attempts")],
    )
    result = llm.ExtractionResult(requirements=[item])
    [req] = llm.to_requirements(PROVISIONS["11.6.2"], result, "m", "abc", INDEX)
    assert req.review.status == ReviewStatus.REJECTED
    assert "'5 attempts' is not in the text" in req.review.notes


def test_extract_provision_writes_drafts_and_replaces_old_ones(tmp_path):
    stale = tmp_path / "REQ-CIR2690-11.7.1-02.yaml"
    stale.write_text("review:\n  status: draft\n")
    client = FakeClient(llm.ExtractionResult(requirements=[_item(MFA_QUOTE)]))

    outcome = llm.extract_provision(client, PROVISIONS["11.7.1"], tmp_path, INDEX, "abc")

    assert (outcome.written, outcome.rejected, outcome.error) == (1, 0, "")
    assert not stale.exists()
    written = yaml.safe_load((tmp_path / "REQ-CIR2690-11.7.1-01.yaml").read_text())
    assert written["source"]["quote"] == MFA_QUOTE


def test_reviewed_requirements_are_never_overwritten(tmp_path):
    reviewed = tmp_path / "REQ-CIR2690-11.7.1-01.yaml"
    reviewed.write_text("review:\n  status: reviewed\n")
    client = FakeClient(llm.ExtractionResult(requirements=[_item(MFA_QUOTE)]))

    outcome = llm.extract_provision(client, PROVISIONS["11.7.1"], tmp_path, INDEX, "abc")

    assert outcome.skipped and not client.calls
    assert reviewed.read_text() == "review:\n  status: reviewed\n"


@pytest.mark.parametrize("stop_reason", ["refusal", "max_tokens"])
def test_incomplete_responses_are_errors_not_output(tmp_path, stop_reason):
    client = FakeClient(llm.ExtractionResult(requirements=[]), stop_reason=stop_reason)
    outcome = llm.extract_provision(client, PROVISIONS["11.7.1"], tmp_path, INDEX, "abc")
    assert outcome.error and outcome.written == 0
    assert not list(tmp_path.iterdir())


# --- evaluation ---------------------------------------------------------------

GOLD = load_gold(ROOT / "eval" / "gold-cir-2024-2690.yaml")


def test_gold_keywords_are_matchable():
    """A keyword missing from the provision text could never be found by a verbatim quote."""
    for number, gold in GOLD.provisions.items():
        text = PROVISIONS[number].text.lower().replace("’", "'")
        for obligation in gold.obligations:
            for keyword in obligation.keywords:
                assert keyword.lower() in text, (number, keyword)


def test_invented_terms():
    item = _item(
        "require the change of authentication credentials initially, at predefined intervals",
        obligation="The entity shall change credentials every 90 days using NIST guidance.",
    )
    result = llm.ExtractionResult(requirements=[item])
    [req] = llm.to_requirements(PROVISIONS["11.6.2"], result, "m", "abc", INDEX)
    assert invented_terms(req, PROVISIONS["11.6.2"].text) == ["90", "days", "nist"]


def test_evaluation_scores_a_known_extraction(tmp_path):
    items = [
        _item("ensure the strength of authentication is appropriate to the classification"),
        _item("terminate inactive sessions after a predefined period of inactivity"),
        _item(
            "require the reset of authentication credentials and the blocking of users "
            "after a predefined number of unsuccessful log-in attempts",
            obligation="The entity shall block users after 5 unsuccessful log-in attempts.",
        ),
        _item("users must change passwords"),  # paraphrase: auto-rejected
    ]
    result = llm.ExtractionResult(requirements=items)
    for req in llm.to_requirements(PROVISIONS["11.6.2"], result, "m", "abc", INDEX):
        llm.write_requirement(tmp_path / f"{req.id}.yaml", req)

    gold = GOLD.model_copy(update={"provisions": {"11.6.2": GOLD.provisions["11.6.2"]}})
    evaluation = evaluate(tmp_path, gold, INDEX)
    [score] = evaluation.scores

    assert (score.extracted, score.quotes_valid, score.accepted) == (4, 3, 3)
    assert score.obligations_found == 3  # strength, inactive sessions, log-in attempts
    assert score.obligations_total == 5
    assert score.count_ok  # 3 accepted, gold range 3-7
    assert list(score.invented.values()) == [["5"]]
    summary = evaluation.summary()
    assert summary["quote_validity"] == 0.75
    assert summary["obligation_recall"] == 0.6


def test_missing_provisions_are_reported(tmp_path):
    evaluation = evaluate(tmp_path, GOLD, INDEX)
    assert evaluation.scores == [] and len(evaluation.not_extracted) == len(GOLD.provisions)


def test_provision_dataclass_is_frozen():
    with pytest.raises(AttributeError):
        PROVISIONS["11.7.1"].number = "x"
    assert replace(PROVISIONS["11.7.1"], number="x").number == "x"
