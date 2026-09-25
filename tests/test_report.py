"""Report assembly, HTML rendering and the narrative validator (with a fake client)."""

import json
from dataclasses import asdict
from types import SimpleNamespace

import pytest
from conftest import scan_run

from nis2scan.registry import CHECKS
from nis2scan.report import narrate as nr
from nis2scan.report.data import load_run, nis2_points
from nis2scan.report.plain import FORMATTERS, explain
from nis2scan.report.render import render


@pytest.fixture
def weak(tmp_path):
    run = scan_run(tmp_path, "weak")
    return run, load_run(run)


# --- report data --------------------------------------------------------------


@pytest.mark.parametrize(
    "article, points",
    [
        ("21(2)(h)", ["21(2)(h)"]),
        ("21(2)(i), (j)", ["21(2)(i)", "21(2)(j)"]),
        ("23(4)", ["23(4)"]),
    ],
)
def test_nis2_points(article, points):
    assert nis2_points(article) == points


def test_one_gap_per_failing_check_most_severe_first(weak):
    _, data = weak
    assert len(data.gaps) == data.check_counts["fail"] == 17
    assert data.gaps[0].finding_id == "CHK-IDP-004"  # the only critical check
    order = ["critical", "high", "medium", "low"]
    assert [order.index(g.severity) for g in data.gaps] == sorted(
        order.index(g.severity) for g in data.gaps
    )


def test_gap_lists_every_breached_requirement_nis2_first(weak):
    _, data = weak
    mfa = next(g for g in data.gaps if g.finding_id == "CHK-IDP-001")
    assert [b.requirement_id for b in mfa.breaches] == [
        "REQ-NIS2-21.2.J",
        "REQ-CIR2690-11.3.2-01",
        "REQ-CIR2690-11.7.1-01",
    ]
    assert "multiple authentication factors" in mfa.breaches[2].quote
    assert mfa.evidence_sha256  # traceable to the hashed evidence file


def test_article_overview_counts_cir_detail(weak):
    _, data = weak
    rows = {a.point: a for a in data.articles}
    assert rows["21(2)(c)"].verdict == "not_satisfied"
    # 4.2.1-01 via the backup age check, 4.2.2-05 via the backup encryption check
    assert rows["21(2)(c)"].detailed_not_satisfied == 2
    assert rows["21(2)(a)"].verdict == "not_assessed"


def test_hardened_has_no_gaps(tmp_path):
    data = load_run(scan_run(tmp_path, "hardened"))
    assert data.gaps == []
    assert data.verdict_counts["not_satisfied"] == 0
    assert data.verdict_counts["partially_evidenced"] == 21


def test_narrative_input_excludes_evidence_paths(weak):
    _, data = weak
    payload = json.dumps(data.narrative_input())
    assert "evidence_sha256" not in payload and "evidence/" not in payload
    assert "CHK-IDP-004" in payload and "multiple authentication factors" in payload
    assert "Restart automatic backups" not in payload  # hand-written text is not data


# --- plain language -------------------------------------------------------------


def test_every_check_has_a_plain_language_formatter(weak):
    assert set(FORMATTERS) == set(CHECKS)


def test_every_weak_gap_is_explained_in_plain_language(weak):
    _, data = weak
    for g in data.gaps:
        assert g.found and g.should, g.finding_id
        assert "{" not in g.found + g.should, g.finding_id  # no raw values leak through
    by_id = {g.finding_id: g for g in data.gaps}
    backup = by_id["CHK-BAK-001"]
    restic = next(a for a in backup.assets if a.asset == "restic")
    assert restic.found == "The newest backup was taken on 1 June 2025, 480 days ago."
    assert backup.should == "A backup no older than 26 hours."
    assert backup.action == "Restart automatic backups" and backup.effort == "change"
    assert "password alone: kari.admin and ola.tech." in by_id["CHK-IDP-001"].found
    assert "26 known critical flaws" in by_id["CHK-VUL-001"].found


@pytest.mark.parametrize(
    "check_id, observed, expected, found",
    [
        ("CHK-BAK-001", {"snapshots": 0}, {"max_age_hours": 26}, "There are no backups at all."),
        (
            "CHK-DOC-002",
            {"document": "plan.md"},
            {"max_review_age_days": 365},
            "The incident plan does not record when it was last reviewed.",
        ),
        (
            "CHK-IDP-003",
            {"passwordPolicy": "length(8)", "min_length": 8},
            {"min_length_at_least": 12},
            "Passwords can be as short as 8 characters.",
        ),
        (
            "CHK-TLS-002",
            {"not_before": "2026-01-01T00:00:00+00:00", "not_after": "2026-10-01", "days_left": 5},
            {"min_days_remaining": 14},
            "The website's certificate expires in 5 days.",
        ),
        (
            "CHK-TLS-003",
            {"http_status": 301, "location": "https://example.org/", "hsts": None},
            {"http_redirects_to_https": True, "hsts": True},
            "Browsers are not told to always use the encrypted site.",
        ),
    ],
)
def test_plain_language_covers_other_failure_branches(check_id, observed, expected, found):
    assert explain(check_id, observed, expected).found == found


def test_unexpected_values_fall_back_to_the_check_message():
    assert explain("CHK-BAK-001", {"unexpected": 1}, {}) is None
    assert explain("CHK-UNKNOWN", {}, {}) is None


# --- rendering ------------------------------------------------------------------


def test_render_without_narrative(weak):
    run, data = weak
    html_path, json_path = render(data, run)
    html = html_path.read_text()
    assert "It is <b>not</b> a statement of NIS2 compliance" in html
    assert all(g.finding_id in html for g in data.gaps)
    assert "Executive summary" not in html
    assert json.loads(json_path.read_text())["narrative"] is None


def test_render_leads_with_the_result_and_what_to_fix_first(weak):
    run, data = weak
    html = render(data, run)[0].read_text()
    assert "All 17 checks failed." in html
    assert "1 problem is critical and 6 are high severity." in html
    assert html.count('<i class="u ns">') == 21 and html.count('<i class="u">') == 64
    fix_first = html[html.index('id="fix-first"') : html.index('id="measures"')]
    assert fix_first.count("<li>") == 7  # the critical and high-severity gaps
    assert fix_first.index("Change the default admin password") < fix_first.index(
        "Restart automatic backups"
    )
    assert "A backup no older than 26 hours." in html
    assert "20 detailed requirements: <b>8 failing</b> · 12 not checked" in html


def test_report_lists_the_systems_scanned(weak):
    run, data = weak
    idp = next(a for a in data.assets if a["section"] == "idp")
    assert (idp["name"], idp["product"], idp["method"]) == (
        "keycloak",
        "keycloak",
        "OpenID configuration",
    )
    html = render(data, run)[0].read_text()
    assert "Systems scanned (9)" in html and "issuer http://127.0.0.1:18081/realms/nordmsp" in html


def test_render_is_self_contained(weak):
    run, data = weak
    html = render(data, run)[0].read_text()
    assert "<script" not in html and "<link" not in html and 'src="' not in html


def test_render_passing_scan(tmp_path):
    run = scan_run(tmp_path, "hardened")
    html = render(load_run(run), run)[0].read_text()
    assert "All 17 checks passed." in html and "No problems found." in html
    assert "partial evidence for 21 of 85 legal requirements" in html
    assert 'id="fix-first"' not in html


def test_render_escapes_scan_data(weak):
    run, data = weak
    data.gaps[0].message = "<script>alert(1)</script>"
    html = render(data, run)[0].read_text()
    assert "<script>alert(1)</script>" not in html


def test_accepted_narrative_is_shown_next_to_its_gap(weak):
    run, data = weak
    narrative = valid_narrative(data)
    result = nr.NarrativeResult(
        "accepted", "claude-opus-5", "high", "v", "t", 1, narrative=narrative.model_dump()
    )
    (run / "narrative.json").write_text(json.dumps(asdict(result)))
    html = render(data, run)[0].read_text()
    assert "Executive summary" in html
    assert f'<a href="#{data.gaps[0].finding_id}">' in html  # sources link to their gaps
    first = html.index(f'id="{data.gaps[0].finding_id}"')
    second = html.index(f'id="{data.gaps[1].finding_id}"')
    assert html.index(narrative.gaps[0].why_it_matters[:40], first) < second


def test_rejected_narrative_is_not_shown(weak):
    run, data = weak
    result = nr.NarrativeResult(
        "rejected", "m", "high", "v", "t", 2, ["gap CHK-X is not explained"]
    )
    (run / "narrative.json").write_text(json.dumps(asdict(result)))
    html = render(data, run)[0].read_text()
    assert "rejected</b> by the validator" in html and "Executive summary" not in html


# --- narrative validation ----------------------------------------------------------


def valid_narrative(data) -> nr.Narrative:
    """A narrative built only from the data, so it must pass."""
    return nr.Narrative(
        executive_summary=f"The scan found {len(data.gaps)} gaps; the most severe is {data.gaps[0].message}.",
        executive_summary_finding_ids=[data.gaps[0].finding_id],
        gaps=[
            nr.GapExplanation(
                finding_id=g.finding_id,
                requirement_ids=[b.requirement_id for b in g.breaches],
                why_it_matters=f"The law asks: {g.breaches[0].quote}. Observed: {g.message}.",
                remediation=[f"Change the configuration to match: {json.dumps(g.expected)}"],
            )
            for g in data.gaps
        ],
    )


def test_valid_narrative_passes(weak):
    _, data = weak
    assert nr.validate(valid_narrative(data), data) == []


def test_missing_and_unknown_gaps_are_caught(weak):
    _, data = weak
    n = valid_narrative(data)
    dropped = n.gaps.pop(0).finding_id
    n.gaps.append(n.gaps[0].model_copy(update={"finding_id": "CHK-FAKE-001"}))
    problems = nr.validate(n, data)
    assert f"failing finding {dropped} is not explained" in problems
    assert "CHK-FAKE-001 is explained but is not a failing finding" in problems


def test_citing_an_unbreached_requirement_is_caught(weak):
    _, data = weak
    n = valid_narrative(data)
    n.gaps[0].requirement_ids.append("REQ-NIS2-21.2.H")  # IDP-004 does not breach 21(2)(h)
    assert any("cites REQ-NIS2-21.2.H" in p for p in nr.validate(n, data))


def test_invented_numbers_and_standards_are_caught(weak):
    _, data = weak
    n = valid_narrative(data)
    n.gaps[0].remediation.append("Rotate credentials every 90 days in line with NIST guidance.")
    problems = nr.validate(n, data)
    # "90" occurs in the scan data (log retention), but not in this gap's data.
    assert (
        f"{data.gaps[0].finding_id}: introduces terms not in its data: 90, days, nist" in problems
    )


def test_versions_in_the_data_are_allowed(weak):
    _, data = weak
    n = valid_narrative(data)
    tls = next(g for g in n.gaps if g.finding_id == "CHK-TLS-001")
    tls.remediation.append("Allow only TLS 1.2 and newer.")  # data says "TLSv1.2"
    assert nr.validate(n, data) == []


@pytest.mark.parametrize(
    "claim", ["The system is compliant.", "It is non-compliant.", "Certified."]
)
def test_compliance_claims_are_forbidden(weak, claim):
    _, data = weak
    n = valid_narrative(data)
    n.executive_summary += " " + claim
    assert any("forbidden term" in p for p in nr.validate(n, data))


def test_ids_in_the_prose_are_caught(weak):
    _, data = weak
    n = valid_narrative(data)
    n.executive_summary += " The worst is CHK-IDP-004 (see also CHK-BAK-001, CHK-IDP-004)."
    n.gaps[0].remediation.append("This addresses REQ-NIS2-21.2.I.")
    problems = nr.validate(n, data)
    assert any(
        p.startswith("executive summary: writes IDs in the text (CHK-IDP-004, CHK-BAK-001)")
        for p in problems
    )
    assert any(p.startswith(f"{n.gaps[0].finding_id}: writes IDs") for p in problems)


# --- narrate() with a fake client -------------------------------------------------


class FakeClient:
    def __init__(self, outputs, stop_reason="end_turn"):
        self.outputs = list(outputs)
        self.calls = []
        self.stop_reason = stop_reason
        self.beta = SimpleNamespace(messages=SimpleNamespace(parse=self._parse))

    def _parse(self, **kwargs):
        self.calls.append(kwargs)
        return SimpleNamespace(
            stop_reason=self.stop_reason, parsed_output=self.outputs.pop(0), model="claude-opus-5"
        )


def test_narrate_retries_once_with_the_validator_feedback(weak):
    _, data = weak
    good = valid_narrative(data)
    bad = good.model_copy(update={"gaps": good.gaps[1:]})
    client = FakeClient([bad, good])

    result = nr.narrate(client, data)

    assert (result.status, result.attempts) == ("accepted", 2)
    retry_prompt = client.calls[1]["messages"][0]["content"]
    assert f"failing finding {data.gaps[0].finding_id} is not explained" in retry_prompt
    assert client.calls[0]["fallbacks"] == "default"
    assert client.calls[0]["output_format"] is nr.Narrative
    assert client.calls[0]["output_config"] == {"effort": nr.EFFORT}


def test_narrate_uses_the_requested_model_and_effort(weak):
    _, data = weak
    client = FakeClient([valid_narrative(data)])
    result = nr.narrate(client, data, model="claude-opus-5-5", effort="medium")
    assert client.calls[0]["model"] == "claude-opus-5-5"
    assert client.calls[0]["output_config"] == {"effort": "medium"}
    assert (result.status, result.effort) == ("accepted", "medium")


def test_narrate_gives_up_after_two_bad_drafts(weak):
    _, data = weak
    bad = valid_narrative(data)
    bad.executive_summary += " The system is compliant."
    result = nr.narrate(FakeClient([bad, bad]), data)
    assert result.status == "rejected" and result.narrative is None
    assert any("forbidden term" in v for v in result.violations)


def test_narrate_rejects_refusals(weak):
    _, data = weak
    client = FakeClient([None, None], stop_reason="refusal")
    result = nr.narrate(client, data)
    assert result.status == "rejected"
    assert result.violations == ["model stopped with refusal"]


def test_no_gaps_means_no_api_call(tmp_path):
    data = load_run(scan_run(tmp_path, "hardened"))
    client = FakeClient([])
    assert nr.narrate(client, data).status == "rejected" and not client.calls
