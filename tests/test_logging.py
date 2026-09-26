"""Log-store adapters, detection and the retention check, on recorded and constructed data."""

import copy
import json

import pytest
from conftest import FIXTURES

from nis2scan.adapters import _http
from nis2scan.adapters.logging import ADAPTERS, LogRetentionEvidence, parse_duration
from nis2scan.adapters.logging import elasticsearch as es_module
from nis2scan.adapters.logging import loki as loki_module
from nis2scan.checks.operations import log_retention
from nis2scan.collectors.logging import detect
from nis2scan.config import LogsTarget, load_profile
from nis2scan.registry import CollectorError

PROFILE = load_profile(FIXTURES.parent.parent.parent / "catalog" / "profile.yaml")
ES = ADAPTERS["elasticsearch"]
LOKI = ADAPTERS["loki"]


def recorded(profile, store):
    return json.loads((FIXTURES / profile / "log_retention" / f"{store}.json").read_text())


@pytest.mark.parametrize("profile", ["weak", "hardened"])
@pytest.mark.parametrize("store", ["loki", "elasticsearch"])
def test_recorded_evidence_is_the_normalised_raw_response(profile, store):
    ev = recorded(profile, store)
    assert ADAPTERS[store].normalize(ev["raw"]).model_dump() == ev["retention"]


def test_live_elasticsearch_setups():
    weak = ES.normalize(recorded("weak", "elasticsearch")["raw"])
    assert [(s.name, s.retention_days) for s in weak.scopes] == [("index app-logs-000001", 7)]
    hardened = ES.normalize(recorded("hardened", "elasticsearch")["raw"])
    # The hidden backing index is judged through its data stream, not on its own.
    assert [(s.name, s.retention_days) for s in hardened.scopes] == [
        ("data stream logs-nordmsp", 180)
    ]


# --- Elasticsearch retention rules ---------------------------------------------------

BASE = {
    "cluster": "http://es",
    "version": "9.5.3",
    "pattern": "*",
    "indices": {},
    "ilm_policies": {},
    "data_streams": {},
}


def es(**parts):
    return ES.normalize({**copy.deepcopy(BASE), **parts})


def test_ilm_policy_without_delete_phase_keeps_forever():
    idx = es(
        indices={"app": {"managed": True, "policy": "hot-only"}},
        ilm_policies={"hot-only": {"delete_after": None}},
    )
    assert idx.scopes[0].retention_days is None and "no delete phase" in idx.scopes[0].source


def test_unmanaged_index_keeps_forever():
    assert es(indices={"app": {"managed": False, "policy": None}}).shortest is None


def test_data_stream_managed_by_ilm_uses_its_policy():
    idx = es(
        data_streams={
            "logs-x": {
                "managed_by": "Index Lifecycle Management",
                "ilm_policy": "30d",
                "lifecycle": {},
            }
        },
        ilm_policies={"30d": {"delete_after": "30d"}},
    )
    assert idx.scopes[0].retention_days == 30


def test_data_stream_lifecycle_without_retention_keeps_forever():
    idx = es(
        data_streams={
            "logs-x": {
                "managed_by": "Data stream lifecycle",
                "ilm_policy": None,
                "lifecycle": {"enabled": True},
            }
        }
    )
    assert idx.scopes[0].retention_days is None


def test_shortest_scope_decides():
    idx = es(
        indices={
            "a": {"managed": True, "policy": "p90"},
            "b": {"managed": True, "policy": "p7"},
            "c": {"managed": False, "policy": None},
        },
        ilm_policies={"p90": {"delete_after": "90d"}, "p7": {"delete_after": "7d"}},
    )
    assert (idx.shortest.name, idx.shortest.retention_days) == ("index b", 7)


def test_nothing_in_scope_is_an_error():
    with pytest.raises(ValueError, match="no indices or data streams match"):
        es()


def test_delete_after_reads_the_delete_phase():
    policy = {
        "policy": {"phases": {"hot": {}, "delete": {"min_age": "14d", "actions": {"delete": {}}}}}
    }
    assert es_module.delete_after(policy) == "14d"
    assert es_module.delete_after({"policy": {"phases": {"hot": {}}}}) is None


# --- Loki retention rules -------------------------------------------------------------


def loki(period="30d", enabled=True, streams=()):
    return LOKI.normalize(
        {
            "source": "http://loki/config",
            "limits_config": {"retention_period": period, "retention_stream": list(streams)},
            "compactor": {"retention_enabled": enabled},
        }
    )


def test_loki_stream_overrides_are_scopes():
    idx = loki("180d", streams=[{"selector": '{app="debug"}', "priority": 1, "period": "24h"}])
    assert (idx.shortest.name, idx.shortest.retention_days) == ('streams {app="debug"}', 1)


@pytest.mark.parametrize("period, enabled", [("0s", True), ("30d", False)])
def test_loki_never_deletes(period, enabled):
    assert loki(period, enabled).shortest is None


def test_elasticsearch_units_parse():
    assert parse_duration("7d").days == 7 and parse_duration("36h").days == 1


# --- the check -----------------------------------------------------------------------


def check(evidence: LogRetentionEvidence):
    return log_retention({"retention": evidence.model_dump()}, PROFILE, None)


def test_check_names_the_scope_when_there_are_several():
    result = check(
        loki("180d", streams=[{"selector": '{app="debug"}', "priority": 1, "period": "24h"}])
    )
    assert result.status == "fail"
    assert result.message == 'Logs are deleted after 1 day (streams {app="debug"})'
    assert result.observed["scope"] == 'streams {app="debug"}'


def test_check_passes_when_nothing_is_deleted():
    result = check(loki("0s"))
    assert result.status == "pass" and "never deleted" in result.message


# --- detection -----------------------------------------------------------------------


def target(**kw):
    return LogsTarget(url="http://store", **kw)


def test_configured_product_skips_detection():
    assert detect(target(product="elasticsearch"), None)["method"] == "configured"
    with pytest.raises(CollectorError, match="unknown log store 'graylog'"):
        detect(target(product="graylog"), None)


def test_secured_elasticsearch_is_recognised_by_its_auth_error(monkeypatch):
    def refuse(url, headers=None):
        raise _http.HttpError(url, 401, '{"error":{"type":"security_exception"}}')

    monkeypatch.setattr(loki_module, "get_json", refuse)
    monkeypatch.setattr(es_module, "get_json", refuse)
    assert detect(target(), None)["product"] == "elasticsearch"


def test_opensearch_is_not_taken_for_elasticsearch(monkeypatch):
    def root(url, headers=None):
        if url.endswith("/"):
            return {
                "tagline": "You Know, for Search",
                "version": {"distribution": "opensearch", "number": "2.19"},
            }
        raise CollectorError("no")

    monkeypatch.setattr(loki_module, "get_json", root)
    monkeypatch.setattr(es_module, "get_json", root)
    with pytest.raises(CollectorError, match="could not recognise the log store"):
        detect(target(), None)


def test_elasticsearch_needs_credentials():
    with pytest.raises(CollectorError, match="needs username and password_env, or api_key_env"):
        es_module._headers(target(), lambda name: "x")
