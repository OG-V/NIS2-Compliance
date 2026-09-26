"""Comparing two scans: fixed, still open, new, and when the comparison may mislead."""

import json

import pytest
from conftest import scan_run

from nis2scan.report.compare import compare, render_comparison
from nis2scan.report.data import load_run


@pytest.fixture(scope="module")
def runs(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("runs")
    return scan_run(tmp, "weak"), scan_run(tmp, "hardened")


def edit(run, name, change):
    path = run / name
    path.write_text(json.dumps(change(json.loads(path.read_text()))))


def test_weak_to_hardened_fixes_everything(runs):
    weak, hardened = runs
    c = compare(load_run(weak), load_run(hardened))
    # Per check and asset: 17 checks, 20 results. The weak lab's restic repository is
    # already encrypted (restic always is), so that one result passes in both scans.
    assert (len(c.fixed), len(c.still_open), len(c.new), len(c.unresolved)) == (19, 0, 0, 0)
    assert c.still_passing == 1
    assert c.warnings == []
    assert c.fixed[0].check_id == "CHK-IDP-004"  # most severe first
    backup = next(ch for ch in c.fixed if (ch.check_id, ch.asset) == ("CHK-BAK-001", "restic"))
    assert backup.before_text.startswith("The newest backup was taken on 1 June 2025")
    assert backup.after_text == "Newest backup is within the allowed age"
    assert backup.topic == "Business continuity and backups"
    access = next(m for m in c.measures if m.point == "21(2)(i)")
    assert (access.before, access.after) == ("not_satisfied", "partially_evidenced")
    assert (access.before_not_satisfied, access.after_not_satisfied) == (8, 0)
    # Document reviews are compared too, in their own colour, as in the gap report.
    assert c.review_change == (
        "Document reviews: 4 not satisfied before; 6 evidenced and 3 partially evidenced now."
    )
    assert (c.before_by_basis["document"], c.after_by_basis["document"]) == (0, 9)


def test_reversed_order_shows_regressions_and_warns(runs):
    weak, hardened = runs
    c = compare(load_run(hardened), load_run(weak))
    assert len(c.new) == 19 and not c.fixed
    assert c.warnings == ["The 'after' scan is older than the 'before' scan."]


def test_same_scan_twice_is_all_still_open(runs):
    weak, _ = runs
    c = compare(load_run(weak), load_run(weak))
    assert len(c.still_open) == 19 and not c.fixed and not c.new


def test_mixed_progress(runs, tmp_path):
    weak, hardened = runs
    after = tmp_path / "after"
    after.mkdir()
    for f in ("scan.json", "verdicts.json", "findings.json"):
        (after / f).write_text((hardened / f).read_text())
    weak_findings = {
        (f["check_id"], f["asset"]): f for f in json.loads((weak / "findings.json").read_text())
    }

    def partly_fixed(findings):
        for f in findings:
            if (f["check_id"], f["asset"]) == ("CHK-BAK-001", "restic"):
                f.update(weak_findings["CHK-BAK-001", "restic"])
            if f["check_id"] == "CHK-SSH-003":
                f["status"] = "error"
        return findings

    edit(after, "findings.json", partly_fixed)
    c = compare(load_run(weak), load_run(after))
    assert (len(c.fixed), len(c.still_open), len(c.unresolved)) == (17, 1, 1)
    assert c.still_open[0].check_id == "CHK-BAK-001"
    assert c.unresolved[0].check_id == "CHK-SSH-003"

    html = render_comparison(weak, after, tmp_path / "diff.html")[0].read_text()
    assert "17 of 19 problems fixed." in html and "1 still open." in html
    assert "Could not compare (1)" in html


def test_changed_profile_and_catalog_are_flagged(runs, tmp_path):
    weak, hardened = runs
    after = tmp_path / "after"
    after.mkdir()
    for f in ("scan.json", "verdicts.json", "findings.json"):
        (after / f).write_text((hardened / f).read_text())
    edit(after, "scan.json", lambda s: s | {"profile_sha256": "0" * 64})
    edit(after, "verdicts.json", lambda v: v[:-1])
    warnings = compare(load_run(weak), load_run(after)).warnings
    assert any("profile changed" in w for w in warnings)
    assert any("catalog changed between the scans (85 and 84" in w for w in warnings)


def test_render_comparison(runs, tmp_path):
    weak, hardened = runs
    html_path, json_path, _ = render_comparison(weak, hardened, tmp_path / "out" / "diff.html")
    html = html_path.read_text()
    assert "All 19 problems fixed." in html and "No new problems." in html
    assert "Default admin credentials are rejected" in html  # fixed items show the goal
    assert "<script" not in html and "<link" not in html and 'src="' not in html
    assert len(json.loads(json_path.read_text())["fixed"]) == 19


def test_comparison_shows_evidence_by_basis(runs, tmp_path):
    weak, hardened = runs
    html = render_comparison(weak, hardened, tmp_path / "diff.html")[0].read_text()
    assert "<b>21</b> partially evidenced by checks" in html
    assert "<b>9</b> evidenced by document review" in html
    assert "6 evidenced and 3 partially evidenced now" in html


def test_review_change_wording():
    from nis2scan.report.compare import _review_change

    assert _review_change({}, {}) == ""
    assert _review_change({"evidenced": 2}, {"evidenced": 2}) == (
        "Document reviews: unchanged (2 evidenced)."
    )
    assert _review_change({}, {"not_assessed": 1}) == (
        "Document reviews: none before; 1 no longer valid now."
    )
