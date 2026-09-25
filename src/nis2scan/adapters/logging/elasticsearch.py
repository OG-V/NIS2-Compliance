"""Elasticsearch: retention of log indices and data streams.

Elasticsearch deletes data only when something is configured to delete it:
- an index lifecycle (ILM) policy with a delete phase: data is deleted `min_age` after
  rollover (or index creation);
- a data stream's own lifecycle: data is deleted after its `data_retention`.
Everything else is kept indefinitely. For each regular index and data stream in scope
(the target's `indices` pattern; hidden and system indices excluded), the adapter
records which of these applies. Uses GET /, /_cat/indices, /<pattern>/_ilm/explain,
/_ilm/policy and /_data_stream with a read-only user or API key.

A data stream is managed by whichever its `next_generation_managed_by` names: data
stream lifecycle, ILM (its `ilm_policy`), or neither.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from nis2scan.adapters._http import HttpError, basic_auth, get_json
from nis2scan.adapters.logging import LogAdapter, LogRetentionEvidence, LogScope, adapter, days
from nis2scan.config import LogsTarget
from nis2scan.registry import CollectorError


def _headers(logs: LogsTarget, secret) -> dict[str, str]:
    if logs.api_key_env:
        return {"Authorization": f"ApiKey {secret(logs.api_key_env)}"}
    if logs.username and logs.password_env:
        return basic_auth(logs.username, secret(logs.password_env))
    raise CollectorError("Elasticsearch needs username and password_env, or api_key_env, set")


def delete_after(policy: dict) -> str | None:
    """The delete phase's min_age of an ILM policy, or None if it never deletes."""
    phases = (policy.get("policy") or {}).get("phases") or {}
    delete = phases.get("delete")
    if not delete or "delete" not in (delete.get("actions") or {}):
        return None
    return delete.get("min_age") or "0d"


@adapter
class Elasticsearch(LogAdapter):
    product = "elasticsearch"
    label = "Elasticsearch"
    needs = ()  # username + password_env, or api_key_env; checked when connecting
    access = (
        "An Elasticsearch user or API key with the cluster privileges monitor and read_ilm, "
        "and the index privileges monitor and view_index_metadata on the log indices"
    )

    def recognise(self, logs: LogsTarget) -> str | None:
        try:
            root = get_json(f"{logs.url.rstrip('/')}/")
        except HttpError as exc:
            # A secured cluster refuses anonymous requests with its own error type.
            if exc.status == 401 and "security_exception" in exc.body:
                return "authentication error (security_exception)"
            return None
        except CollectorError:
            return None
        version = root.get("version") or {}
        if (
            root.get("tagline") == "You Know, for Search"
            and version.get("distribution") != "opensearch"
        ):
            return f"root endpoint (Elasticsearch {version.get('number')})"
        return None

    def check_access(self, logs: LogsTarget, secret) -> None:
        get_json(f"{logs.url.rstrip('/')}/_ilm/policy", _headers(logs, secret))

    def fetch(self, logs: LogsTarget, secret) -> dict[str, Any]:
        base, headers = logs.url.rstrip("/"), _headers(logs, secret)
        pattern = quote(logs.indices, safe="*,-")
        # Open, non-hidden indices only: data stream backing indices (.ds-*) are hidden
        # and are judged through their data stream.
        open_only = "expand_wildcards=open"
        indices = get_json(
            f"{base}/_cat/indices/{pattern}?format=json&h=index&{open_only}", headers
        )
        explain = (
            get_json(f"{base}/{pattern}/_ilm/explain?only_managed=false&{open_only}", headers)[
                "indices"
            ]
            if indices
            else {}
        )
        try:
            streams = get_json(f"{base}/_data_stream/{pattern}", headers)["data_streams"]
        except HttpError as exc:
            if exc.status != 404:
                raise
            streams = []
        index_rows = {
            i["index"]: {
                "managed": explain.get(i["index"], {}).get("managed", False),
                "policy": explain.get(i["index"], {}).get("policy"),
            }
            for i in indices
        }
        stream_rows = {
            s["name"]: {
                "managed_by": s.get("next_generation_managed_by"),
                "ilm_policy": s.get("ilm_policy"),
                "lifecycle": {
                    k: (s.get("lifecycle") or {}).get(k)
                    for k in ("enabled", "data_retention", "effective_retention")
                },
            }
            for s in streams
        }
        # Only the policies in-scope data uses; a cluster ships dozens of built-in ones.
        used = {r["policy"] for r in index_rows.values()} | {
            r["ilm_policy"] for r in stream_rows.values()
        }
        policies = get_json(f"{base}/_ilm/policy", headers)
        return {
            "cluster": base,
            "version": get_json(f"{base}/", headers).get("version", {}).get("number"),
            "pattern": logs.indices,
            "indices": index_rows,
            "ilm_policies": {
                name: {"delete_after": delete_after(p)}
                for name, p in policies.items()
                if name in used
            },
            "data_streams": stream_rows,
        }

    def normalize(self, raw: dict[str, Any]) -> LogRetentionEvidence:
        policies = raw["ilm_policies"]

        def by_policy(name: str | None) -> tuple[int | None, str]:
            after = (policies.get(name) or {}).get("delete_after") if name else None
            if after is None:
                return None, f"ILM policy {name} has no delete phase" if name else "no ILM policy"
            return days(after), f"ILM policy {name} deletes after {after}"

        scopes = []
        backing = tuple(f".ds-{stream}-" for stream in raw["data_streams"])
        for name, index in sorted(raw["indices"].items()):
            if backing and name.startswith(backing):
                continue  # judged through its data stream below
            if index["managed"]:
                retention, source = by_policy(index["policy"])
            else:
                retention, source = None, "no lifecycle policy: never deleted"
            scopes.append(LogScope(name=f"index {name}", retention_days=retention, source=source))
        for name, stream in sorted(raw["data_streams"].items()):
            managed_by = stream.get("managed_by") or ""
            lifecycle = stream.get("lifecycle") or {}
            if "Data stream lifecycle" in managed_by:
                period = lifecycle.get("effective_retention") or lifecycle.get("data_retention")
                retention = days(period)
                source = (
                    f"data stream lifecycle retains {period}"
                    if period
                    else "data stream lifecycle without retention"
                )
            elif "Index Lifecycle Management" in managed_by:
                retention, source = by_policy(stream.get("ilm_policy"))
            else:
                retention, source = None, "unmanaged data stream: never deleted"
            scopes.append(
                LogScope(name=f"data stream {name}", retention_days=retention, source=source)
            )
        if not scopes:
            raise ValueError(f"no indices or data streams match {raw['pattern']!r}")
        return LogRetentionEvidence(store=raw["cluster"], scopes=scopes)
