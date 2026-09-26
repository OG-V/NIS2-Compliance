"""Splunk: retention of each event index, from the management REST API (port 8089).

Splunk freezes an index's oldest data once it is older than `frozenTimePeriodInSecs`,
or earlier once the index reaches `maxTotalDataSizeMB`. Frozen data is deleted, unless
`coldToFrozenDir` or `coldToFrozenScript` archives it. So an index is:
- kept indefinitely, if frozen data is archived;
- otherwise deleted after its frozen period, and possibly sooner when near its size
  cap, which the evidence notes (the time that happens after cannot be known).
Splunk's internal indexes (names starting with "_") are left out unless the target's
`indices` pattern asks for them. Uses GET /services/data/indexes with a token or user.
Built from the Splunk REST API reference.
"""

from __future__ import annotations

import fnmatch
from typing import Any

from nis2scan.adapters._http import HttpError, basic_auth, get_json, trust
from nis2scan.adapters.logging import LogAdapter, LogRetentionEvidence, LogScope, adapter
from nis2scan.config import LogsTarget
from nis2scan.registry import CollectorError

NEAR_CAP = 0.9  # an index this full of its size cap is already, or soon, cut by size
DAY = 86_400


def _auth(logs: LogsTarget, secret) -> dict[str, str]:
    if logs.token_env:
        return {"Authorization": f"Bearer {secret(logs.token_env)}"}
    if logs.username and logs.password_env:
        return basic_auth(logs.username, secret(logs.password_env))
    raise CollectorError("Splunk needs token_env, or username and password_env, set")


def _get(logs: LogsTarget, secret, path: str) -> Any:
    context = trust(str(logs.ca_file) if logs.ca_file else None)
    return get_json(f"{logs.url.rstrip('/')}{path}", _auth(logs, secret), context)


@adapter
class Splunk(LogAdapter):
    product = "splunk"
    label = "Splunk"
    access = (
        "A Splunk authentication token (or user) whose role can read the settings of the "
        "log indexes, for the management API on port 8089, and the server's certificate "
        "if it is self-signed"
    )

    def recognise(self, logs: LogsTarget, secret) -> str | None:
        if not logs.url:
            return None
        context = trust(str(logs.ca_file) if logs.ca_file else None)
        try:
            get_json(f"{logs.url.rstrip('/')}/services/server/info?output_mode=json", None, context)
        except HttpError as exc:
            server = (exc.headers.get("Server") or "") if exc.headers else ""
            return "its Server header (Splunkd)" if "Splunkd" in server else None
        except CollectorError:
            return None
        return None

    def check_access(self, logs: LogsTarget, secret) -> None:
        _get(logs, secret, "/services/data/indexes?output_mode=json&count=1")

    def fetch(self, logs: LogsTarget, secret) -> dict[str, Any]:
        listing = _get(logs, secret, "/services/data/indexes?output_mode=json&count=0&datatype=all")
        keep = (
            "frozenTimePeriodInSecs",
            "maxTotalDataSizeMB",
            "currentDBSizeMB",
            "coldToFrozenDir",
            "coldToFrozenScript",
            "disabled",
            "datatype",
        )
        indexes = {
            e["name"]: {k: (e.get("content") or {}).get(k) for k in keep}
            for e in listing.get("entry", [])
            if fnmatch.fnmatch(e["name"], logs.indices)
            and (not e["name"].startswith("_") or logs.indices.startswith("_"))
        }
        return {"server": logs.url.rstrip("/"), "pattern": logs.indices, "indexes": indexes}

    def normalize(self, raw: dict[str, Any]) -> LogRetentionEvidence:
        scopes = []
        for name, index in sorted(raw["indexes"].items()):
            if index.get("disabled"):
                continue
            seconds = int(index.get("frozenTimePeriodInSecs") or 0)
            cap, size = index.get("maxTotalDataSizeMB"), index.get("currentDBSizeMB")
            near_cap = bool(cap) and float(size or 0) >= NEAR_CAP * float(cap)
            if index.get("coldToFrozenDir") or index.get("coldToFrozenScript"):
                retention, source = (
                    None,
                    f"frozen after {seconds // DAY} days and archived, not deleted",
                )
            else:
                retention = seconds // DAY
                source = f"frozenTimePeriodInSecs {seconds} ({retention} days)"
                if near_cap:
                    source += f"; at {size} of its {cap} MB cap, so data may be deleted sooner"
            scopes.append(LogScope(name=f"index {name}", retention_days=retention, source=source))
        if not scopes:
            raise ValueError(f"no enabled indexes match {raw['pattern']!r}")
        return LogRetentionEvidence(store=raw["server"], scopes=scopes)
