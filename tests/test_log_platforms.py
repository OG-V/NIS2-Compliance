"""Splunk and Microsoft Sentinel log adapters, against documented API responses."""

import json
from pathlib import Path

import pytest

from nis2scan.adapters import _azure, _http
from nis2scan.adapters.logging import ADAPTERS
from nis2scan.adapters.logging import sentinel as sentinel_module
from nis2scan.adapters.logging import splunk as splunk_module
from nis2scan.checks.operations import log_retention
from nis2scan.collectors.logging import detect
from nis2scan.config import LogsTarget, load_profile
from nis2scan.registry import CollectorError

FIXTURES = Path(__file__).parent / "fixtures"
PROFILE = load_profile(Path(__file__).parent.parent / "catalog" / "profile.yaml")
SPLUNK = json.loads((FIXTURES / "splunk" / "documented.json").read_text())
SENTINEL = json.loads((FIXTURES / "sentinel" / "documented.json").read_text())


def secret(name):
    return {"SPLUNK_TOKEN": "tok", "SPLUNK_PW": "pw", "AZ_SECRET": "az"}[name]


def check(evidence):
    return log_retention({"retention": evidence.model_dump()}, PROFILE, None)


# --- Splunk -----------------------------------------------------------------------------

SPLUNK_TARGET = LogsTarget(url="https://splunk01:8089", token_env="SPLUNK_TOKEN")


@pytest.fixture
def fake_splunk(monkeypatch):
    calls = []

    def get_json(url, headers=None, context=None):
        calls.append((url, headers))
        return {"entry": SPLUNK["entry"]}

    monkeypatch.setattr(splunk_module, "get_json", get_json)
    return calls


def test_splunk_indexes_become_scopes(fake_splunk):
    store = ADAPTERS["splunk"].normalize(ADAPTERS["splunk"].fetch(SPLUNK_TARGET, secret))
    scopes = {s.name: s for s in store.scopes}
    # Internal indexes are left out; disabled ones hold nothing to retain.
    assert set(scopes) == {"index main", "index security", "index firewall", "index audit_archive"}
    assert scopes["index main"].retention_days == 2184
    assert scopes["index audit_archive"].retention_days is None  # archived, not deleted
    assert "may be deleted sooner" in scopes["index security"].source
    assert store.shortest.name == "index firewall"


def test_splunk_check_names_the_short_index(fake_splunk):
    result = check(ADAPTERS["splunk"].normalize(ADAPTERS["splunk"].fetch(SPLUNK_TARGET, secret)))
    assert (result.status, result.message) == (
        "fail",
        "Logs are deleted after 30 days (index firewall)",
    )


def test_splunk_internal_indexes_on_request(fake_splunk):
    raw = ADAPTERS["splunk"].fetch(
        LogsTarget(url="https://s:8089", token_env="SPLUNK_TOKEN", indices="_*"), secret
    )
    assert list(raw["indexes"]) == ["_internal"]


def test_splunk_token_or_password(fake_splunk):
    ADAPTERS["splunk"].check_access(SPLUNK_TARGET, secret)
    assert fake_splunk[-1][1] == {"Authorization": "Bearer tok"}
    ADAPTERS["splunk"].check_access(
        LogsTarget(url="https://s:8089", username="scanner", password_env="SPLUNK_PW"), secret
    )
    assert fake_splunk[-1][1]["Authorization"].startswith("Basic ")
    with pytest.raises(
        CollectorError, match="Splunk needs token_env, or username and password_env"
    ):
        ADAPTERS["splunk"].check_access(LogsTarget(url="https://s:8089"), secret)


def test_splunk_is_recognised_by_its_server_header(monkeypatch):
    class Headers(dict):
        def get(self, key, default=None):
            return super().get(key, default)

    def refuse(url, headers=None, context=None):
        raise _http.HttpError(
            url,
            401,
            "<response>call not properly authenticated</response>",
            Headers({"Server": "Splunkd"}),
        )

    monkeypatch.setattr(splunk_module, "get_json", refuse)
    for other in ("loki", "elasticsearch"):
        monkeypatch.setattr(ADAPTERS[other], "recognise", lambda logs, secret: None)
    assert detect(SPLUNK_TARGET, secret)["method"] == "its Server header (Splunkd)"


# --- Microsoft Sentinel ------------------------------------------------------------------

SENTINEL_TARGET = LogsTarget(
    subscription="00000000-0000-0000-0000-00000000bbbb",
    tenant="contoso.onmicrosoft.com",
    client_id="11111111-2222-3333-4444-555555555555",
    client_secret_env="AZ_SECRET",
)


@pytest.fixture
def fake_azure(monkeypatch):
    def get_json(url, headers=None, context=None):
        assert headers == {"Authorization": "Bearer arm"}
        if "/onboardingStates" in url:
            return {
                "value": SENTINEL["onboardingStates"][url.split("/workspaces/")[1].split("/")[0]]
            }
        if "/tables" in url:
            return {"value": SENTINEL["tables"][url.split("/workspaces/")[1].split("/")[0]]}
        return {"value": SENTINEL["workspaces"]}

    monkeypatch.setattr(sentinel_module, "client_credentials_token", lambda *args: "arm")
    monkeypatch.setattr(_azure, "get_json", get_json)


def test_sentinel_workspace_and_tables(fake_azure):
    store = ADAPTERS["sentinel"].normalize(ADAPTERS["sentinel"].fetch(SENTINEL_TARGET, secret))
    scopes = {s.name: s.retention_days for s in store.scopes}
    # Only the workspace with Sentinel; tables on the default are covered by it.
    assert scopes == {
        "workspace law-sentinel (tables on its default)": 90,
        "table law-sentinel/SigninLogs": 730,  # long-term retention counts
        "table law-sentinel/Syslog": 30,
    }


def test_sentinel_check_names_the_short_table(fake_azure):
    result = check(
        ADAPTERS["sentinel"].normalize(ADAPTERS["sentinel"].fetch(SENTINEL_TARGET, secret))
    )
    assert (result.status, result.message) == (
        "fail",
        "Logs are deleted after 30 days (table law-sentinel/Syslog)",
    )


def test_sentinel_named_workspace_is_read_even_without_sentinel(fake_azure):
    named = LogsTarget(**{**SENTINEL_TARGET.model_dump(), "workspace": "law-app"})
    store = ADAPTERS["sentinel"].normalize(ADAPTERS["sentinel"].fetch(named, secret))
    assert [s.name for s in store.scopes] == ["workspace law-app (tables on its default)"]
    with pytest.raises(CollectorError, match="no workspace named 'nope'"):
        ADAPTERS["sentinel"].fetch(
            LogsTarget(**{**SENTINEL_TARGET.model_dump(), "workspace": "nope"}), secret
        )


def test_sentinel_is_recognised_after_signing_in(fake_azure):
    for other in ("loki", "elasticsearch", "splunk"):
        assert ADAPTERS[other].recognise(SENTINEL_TARGET, secret) is None  # no url
    assert (
        detect(SENTINEL_TARGET, secret)["method"]
        == "Sentinel onboarding state (workspace law-sentinel)"
    )


def test_sentinel_needs_its_settings():
    with pytest.raises(
        CollectorError, match="needs subscription, tenant, client_id and client_secret_env"
    ):
        ADAPTERS["sentinel"].fetch(LogsTarget(subscription="x"), secret)


def test_a_log_store_needs_a_place():
    with pytest.raises(ValueError, match="needs url, or subscription"):
        LogsTarget()


def test_sentinel_live_workspace():
    raw = json.loads((FIXTURES / "sentinel" / "live-workspace.json").read_text())
    store = ADAPTERS["sentinel"].normalize(raw)
    assert {s.name: s.retention_days for s in store.scopes} == {
        "workspace nis2scan (tables on its default)": 30,
        "table nis2scan/Alert": 60,
    }
    assert raw["workspaces"][0]["tables_on_default"] == 841
    result = check(store)
    assert (result.status, result.message) == (
        "fail",
        "Logs are deleted after 30 days (workspace nis2scan (tables on its default))",
    )
