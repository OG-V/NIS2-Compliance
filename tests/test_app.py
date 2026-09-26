"""The desktop app: engagement folders, the register editor, jobs and the local server."""

import json
import shutil
import threading
import time
import urllib.error
import urllib.request
from http.cookiejar import CookieJar

import pytest
import yaml
from conftest import ROOT, FixtureContext

from nis2scan.app import jobs, register
from nis2scan.app import workspace as ws
from nis2scan.app.server import serve
from nis2scan.config import load_target

ENGAGEMENT = {
    "client": "Acme Corp",
    "authorised_by": "Jane Smith, CIO",
    "authorised_on": "2026-01-01",
    "valid_until": "2099-12-31",
}


@pytest.fixture(autouse=True)
def config_dir(tmp_path, monkeypatch):
    """Keep recent engagements and the API key out of the real user profile."""
    monkeypatch.setattr(ws, "CONFIG_DIR", tmp_path / "config")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def lab_engagement(tmp_path):
    """An engagement folder for the lab, with its own copy of the hardened documents."""
    folder = tmp_path / "acme"
    shutil.copytree(ROOT / "lab" / "profiles" / "hardened" / "org", folder / "documents")
    raw = yaml.safe_load((ROOT / "lab" / "target.yaml").read_text())
    raw["env_file"] = []
    raw["documents"]["dir"] = "documents"
    assert ws.save_raw(folder, raw) == []
    return folder


# --- engagement folders -------------------------------------------------------------------


def test_saving_validates_first_and_writes_nothing_invalid(tmp_path):
    folder = tmp_path / "new"
    raw = ws.blank(folder) | {"web": [{"name": "www", "host": "", "http_port": 80}]}
    problems = ws.save_raw(folder, raw)
    assert {tuple(p["loc"]) for p in problems} >= {
        ("engagement", "client"),
        ("web", "0", "https_port"),
    }
    assert not (folder / ws.TARGET).exists()


def test_saved_target_scans_like_a_hand_written_one(tmp_path):
    folder = tmp_path / "new"
    raw = ws.blank(folder)
    raw["engagement"] |= ENGAGEMENT
    raw["web"] = [{"name": "www", "host": "www.example", "https_port": 443, "http_port": 80}]
    assert ws.save_raw(folder, raw) == []
    target = load_target(folder / ws.TARGET)
    assert target.engagement.client == "Acme Corp" and target.web[0].host == "www.example"
    assert target.env_file == [folder / ws.SECRETS]
    assert ws.recent()[0] == {"path": str(folder), "label": "Acme Corp", "opened": str(ws.today())}


def test_a_hand_written_target_is_backed_up_once(tmp_path):
    folder = tmp_path / "e"
    folder.mkdir()
    (folder / ws.TARGET).write_text("# notes that matter\n" + yaml.safe_dump({"name": "e"}))
    raw = ws.read_raw(folder) | {"engagement": ENGAGEMENT}
    ws.save_raw(folder, raw)
    ws.save_raw(folder, raw)
    assert (folder / "target.yaml.bak").read_text().startswith("# notes that matter")


def test_credentials_stay_out_of_the_target(tmp_path):
    folder = tmp_path / "e"
    ws.store_secret(folder, "IDP_SSO_ADMIN_PASSWORD", "hunter2")
    ws.store_secret(folder, "IDP_SSO_ADMIN_PASSWORD", "hunter3")  # replaced, not duplicated
    path = folder / ws.SECRETS
    assert path.read_text() == "IDP_SSO_ADMIN_PASSWORD=hunter3\n"
    assert path.stat().st_mode & 0o777 == 0o600
    raw = {"env_file": [ws.SECRETS], "idp": [{"admin_password_env": "IDP_SSO_ADMIN_PASSWORD"}],
           "logs": [{"password_env": "ES_PASSWORD"}]}  # fmt: skip
    assert ws.secrets_set(folder, raw) == {"ES_PASSWORD": False, "IDP_SSO_ADMIN_PASSWORD": True}
    assert ws.secret_name("idp", "sso.acme", "admin_password_env") == "IDP_SSO_ACME_ADMIN_PASSWORD"
    with pytest.raises(ws.WorkspaceError):
        ws.store_secret(folder, "X", "two\nlines")


def test_new_folders_and_file_listings(tmp_path):
    folder = ws.new_folder(tmp_path, 'Acme: NIS2/2026 "final"')
    assert folder.parent == tmp_path and "/" not in folder.name and ":" not in folder.name
    (folder / "docs" / "sub").mkdir(parents=True)
    (folder / "docs" / "policy.md").write_text("x")
    (folder / "docs" / "sub" / "plan.pdf").write_text("x")
    (folder / "docs" / ".hidden").write_text("x")
    assert ws.files(folder, "docs") == ["policy.md", "sub/plan.pdf"]


# --- the evidence register -----------------------------------------------------------------

REVIEW = {
    "requirement": "REQ-NIS2-21.2.F",
    "documents": ["evidence/log-review-procedure.md"],
    "verdict": "partially_evidenced",
    "reviewed_by": "Test Reviewer, consultant",
    "reviewed_on": "2026-09-20",
    "rationale": "Weekly log reviews are recorded; nothing else shows the measures work.",
}


def test_a_review_is_appended_and_the_register_keeps_its_comments(tmp_path):
    folder = lab_engagement(tmp_path)
    path = folder / "documents" / "evidence-register.yaml"
    before = path.read_text()
    register.add_review(folder, REVIEW)
    after = path.read_text()
    assert after.startswith(before.rstrip("\n"))  # appended, comments intact
    state = register.state(folder)
    added = next(r for r in state["reviews"] if r["requirement"] == REVIEW["requirement"])
    assert (
        added["counts_as"] == "partially_evidenced" and len(added["documents"][0]["sha256"]) == 64
    )
    assert state["problems"] == []


@pytest.mark.parametrize(
    "change, message",
    [
        ({"requirement": "REQ-NIS2-21.2.A"}, "already reviewed"),
        ({"requirement": "REQ-NIS2-21.2.H"}, "covered by automated checks"),
        ({"documents": ["gone.md"]}, "document not found: gone.md"),
        ({"rationale": ""}, "rationale"),
        ({"documents": []}, "needs at least one reviewed document"),
    ],
)
def test_reviews_the_register_would_not_apply_are_refused(tmp_path, change, message):
    folder = lab_engagement(tmp_path)
    before = (folder / "documents" / "evidence-register.yaml").read_text()
    with pytest.raises(ws.WorkspaceError, match=message):
        register.add_review(folder, REVIEW | change)
    assert (folder / "documents" / "evidence-register.yaml").read_text() == before


def test_editing_a_review_changes_only_its_entry(tmp_path):
    folder = lab_engagement(tmp_path)
    path = folder / "documents" / "evidence-register.yaml"
    before = path.read_text()
    change = REVIEW | {
        "requirement": "REQ-NIS2-21.2.G",
        "documents": ["evidence/security-training-2026.md"],
        "verdict": "evidenced",
        "valid_until": "2027-06-30",
        "rationale": "Every staff member completed the course; a hygiene policy now exists.",
    }
    register.update_review(folder, "REQ-NIS2-21.2.G", change)
    after = path.read_text()
    assert after.startswith(before.split("  - requirement: REQ-NIS2-21.2.G")[0])  # header kept
    assert "Fictional, like the rest of the lab." in after  # comments survive
    reviews = {r["requirement"]: r for r in register.state(folder)["reviews"]}
    assert len(reviews) == 9 and reviews["REQ-NIS2-21.2.G"]["verdict"] == "evidenced"
    assert reviews["REQ-NIS2-21.2.G"]["reviewed_by"] == "Test Reviewer, consultant"
    assert reviews["REQ-NIS2-21.2.D"]["reviewed_by"] == "Ingrid Solberg, external consultant"
    assert not (path.with_suffix(".yaml.bak")).exists()  # edited in place, not rewritten


def test_deleting_a_review(tmp_path):
    folder = lab_engagement(tmp_path)
    path = folder / "documents" / "evidence-register.yaml"
    order = [r["requirement"] for r in register.state(folder)["reviews"]]
    register.delete_review(folder, order[1])  # one in the middle, with a folded rationale
    assert [r["requirement"] for r in register.state(folder)["reviews"]] == order[:1] + order[2:]
    register.delete_review(folder, order[-1])  # the last one
    assert [r["requirement"] for r in register.state(folder)["reviews"]] == order[:1] + order[2:-1]
    assert register.state(folder)["problems"] == []
    assert path.read_text().startswith("# Evidence register")
    with pytest.raises(ws.WorkspaceError, match="has no review"):
        register.delete_review(folder, order[1])


def test_a_review_cannot_move_to_another_requirement(tmp_path):
    folder = lab_engagement(tmp_path)
    with pytest.raises(ws.WorkspaceError, match="cannot move"):
        register.update_review(folder, "REQ-NIS2-21.2.G", REVIEW)
    with pytest.raises(ws.WorkspaceError, match="has no review"):
        register.update_review(folder, REVIEW["requirement"], REVIEW)


def test_editing_a_register_the_app_did_not_lay_out(tmp_path):
    folder = lab_engagement(tmp_path)
    path = folder / "documents" / "evidence-register.yaml"
    reviews = yaml.safe_load(path.read_text())["reviews"]
    path.write_text(yaml.safe_dump({"reviews": reviews}, default_flow_style=True))  # one line
    register.delete_review(folder, "REQ-NIS2-21.2.G")
    assert path.with_suffix(".yaml.bak").exists()  # rewritten as data, original kept
    assert "REQ-NIS2-21.2.G" not in [r["requirement"] for r in register.state(folder)["reviews"]]


def test_reviewing_one_document_changes_several_reviews_at_once(tmp_path):
    folder = lab_engagement(tmp_path)
    doc = "evidence/log-review-procedure.md"
    add = REVIEW | {"documents": [doc]}
    extend = REVIEW | {  # an existing review gains this document as well
        "requirement": "REQ-CIR2690-3.2.3-01",
        "documents": [doc],
        "verdict": "partially_evidenced",
        "rationale": "Logs are reviewed weekly; how long they are kept is not documented.",
    }
    register.apply_changes(
        folder,
        [
            {"requirement": REVIEW["requirement"], "entry": add},
            {"requirement": "REQ-CIR2690-3.2.3-01", "entry": extend},
            {"requirement": "REQ-CIR2690-3.2.4-01", "delete": True},
        ],
    )
    reviews = {r["requirement"]: r for r in register.state(folder)["reviews"]}
    assert REVIEW["requirement"] in reviews and "REQ-CIR2690-3.2.3-01" in reviews
    assert "REQ-CIR2690-3.2.4-01" not in reviews


def test_one_bad_change_leaves_the_register_untouched(tmp_path):
    folder = lab_engagement(tmp_path)
    path = folder / "documents" / "evidence-register.yaml"
    before = path.read_text()
    with pytest.raises(ws.WorkspaceError, match="rationale"):
        register.apply_changes(
            folder,
            [
                {"requirement": REVIEW["requirement"], "entry": REVIEW},
                {"requirement": "REQ-NIS2-21.2.G", "entry": REVIEW | {
                    "requirement": "REQ-NIS2-21.2.G", "rationale": ""}},
            ],
        )  # fmt: skip
    assert path.read_text() == before


def test_documents_are_read_for_the_reviewer(tmp_path):
    folder = lab_engagement(tmp_path)
    doc = register.document_text(folder, "evidence/backup-plan.md")
    assert "Backup and Recovery Plan" in doc["text"] and len(doc["sha256"]) == 64
    with pytest.raises(ws.WorkspaceError, match="not in the documents folder"):
        register.document_text(folder, "../target.yaml")


def test_starting_a_register(tmp_path):
    folder = lab_engagement(tmp_path)
    raw = ws.read_raw(folder)
    del raw["documents"]["evidence_register"]
    ws.save_raw(folder, raw)
    assert register.create(folder) == "evidence-register.yaml"  # the lab's own is kept
    assert ws.read_raw(folder)["documents"]["evidence_register"] == "evidence-register.yaml"
    (folder / "documents" / "evidence-register.yaml").unlink()
    register.create(folder)
    state = register.state(folder)
    assert state["exists"] and state["reviews"] == [] and len(state["requirements"]) == 64


# --- jobs ----------------------------------------------------------------------------------------


def wait(job):
    for _ in range(600):
        if job.state != "running":
            return job
        time.sleep(0.05)
    raise TimeoutError(job.kind)


def test_access_check_reports_each_system_in_turn(tmp_path):
    folder = tmp_path / "docs-only"
    raw = ws.blank(folder) | {"engagement": ENGAGEMENT}
    shutil.copytree(ROOT / "lab" / "profiles" / "weak" / "org", folder / "documents")
    raw["documents"] = {"dir": "documents", "ir_plan": "incident-response.md",
                        "asset_inventory": "missing.yaml"}  # fmt: skip
    ws.save_raw(folder, raw)
    job = wait(jobs.start("access", jobs.check_access, folder))
    assert job.state == "done", job.error
    types = [e["type"] for e in job.events]
    assert types == ["authorisation", "plan", "probing", "system"]
    (system,) = job.result["systems"]
    assert [a["status"] for a in system["access"]] == ["ok", "missing"]
    assert job.result["ready"] is False


def test_scan_job_reports_progress_and_writes_the_report(tmp_path):
    folder = lab_engagement(tmp_path)

    class Recorded(jobs.ProgressContext, FixtureContext):
        def __init__(self, target, job, total):
            FixtureContext.__init__(self, target, "weak")
            self.job, self.total, self.done = job, total, 0

    job = wait(jobs.start("scan", jobs.scan, folder, Recorded))
    assert job.state == "done", job.error
    collected = [e for e in job.events if e["type"] == "collected"]
    assert collected and collected[-1]["done"] == len(collected)
    assert job.events[0]["total"] >= len(collected) - 1  # the estimate is close
    result = job.result
    assert result["checks"]["fail"] == 17 and result["gaps"][0]["severity"] == "critical"
    run = folder / ws.RESULTS / result["run"]
    assert (run / "report.html").is_file()
    assert ws.runs(folder)[0]["id"] == result["run"]


def test_scans_outside_the_authorisation_are_refused(tmp_path):
    folder = lab_engagement(tmp_path)
    raw = ws.read_raw(folder)
    raw["engagement"]["valid_until"] = "2020-01-31"
    raw["engagement"]["authorised_on"] = "2020-01-01"
    ws.save_raw(folder, raw)
    job = wait(jobs.start("scan", jobs.scan, folder))
    assert job.state == "failed" and job.error.startswith("Scan refused")
    assert not (folder / ws.RESULTS).exists()


def test_ai_steps_need_a_key(tmp_path):
    folder = lab_engagement(tmp_path)
    job = wait(jobs.start("suggest", jobs.suggest, folder, ["evidence/backup-plan.md"]))
    assert job.state == "failed" and ("API key" in job.error or "not installed" in job.error)
    jobs.save_api_key("sk-test")
    assert jobs.api_key() == "sk-test"
    assert (ws.CONFIG_DIR / "anthropic.env").stat().st_mode & 0o777 == 0o600


# --- the local server ------------------------------------------------------------------------------


@pytest.fixture
def app():
    server, _, url = serve(0, exit_when_closed=False)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield url
    server.shutdown()
    server.server_close()


def client(url):
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
    opener.open(url)  # the launch link sets the session cookie
    base = url.split("/?")[0]

    def call(path, body=None, headers=None):
        data = None if body is None else json.dumps(body).encode()
        h = {"Content-Type": "application/json"} if body is not None else {}
        req = urllib.request.Request(base + path, data, h | (headers or {}))
        try:
            with opener.open(req) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    return call


def test_the_server_needs_the_launch_token(app):
    base = app.split("/?")[0]
    for path in ("/", "/api/state", "/report"):
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(base + path)
        assert err.value.code == 403
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(base + "/?t=wrong")
    status, body = client(app)("/api/state")
    assert status == 200 and json.loads(body)["busy"] is False


def test_the_server_refuses_other_hosts_and_form_posts(app):
    call = client(app)
    assert call("/api/state", headers={"Host": "evil.example"})[0] == 403
    # A cross-site form can post only simple content types; the API takes JSON only.
    status, _ = call("/api/open", {"folder": "/"}, {"Content-Type": "text/plain"})
    assert status == 415


def test_open_save_and_report_through_the_api(app, tmp_path):
    call = client(app)
    folder = lab_engagement(tmp_path)
    status, body = call("/api/open", {"folder": str(folder)})
    opened = json.loads(body)
    assert status == 200 and opened["exists"] and opened["problems"] == []
    raw = opened["raw"]
    raw["idp"][0]["admin_password_env"] = None
    status, body = call(
        "/api/save",
        {"folder": str(folder), "raw": raw,
         "secrets": [{"section": "idp", "index": 0, "field": "admin_password_env", "value": "pw"}]},
    )  # fmt: skip
    saved = json.loads(body)
    assert (
        saved["saved"]
        and saved["raw"]["idp"][0]["admin_password_env"] == "IDP_KEYCLOAK_ADMIN_PASSWORD"
    )
    assert "pw" not in (folder / ws.TARGET).read_text()
    status, body = call("/api/save", {"folder": str(folder), "raw": raw,
                        "secrets": [{"section": "idp", "index": 0, "field": "realm", "value": "x"}]})  # fmt: skip
    assert status == 400 and b"unexpected credential field" in body
    # Reports are served only from the engagement's results.
    assert call(f"/report?folder={folder}&run=..%2F..%2Fetc")[0] == 404
    assert call("/static/../workspace.py")[0] == 404
