"""Grafana Loki: retention from the running configuration (/config).

Loki deletes logs only when the compactor's retention is enabled. The global period
is `limits_config.retention_period`; `limits_config.retention_stream` can set shorter
or longer periods for streams matching a selector. A period of 0 means "never
delete". /config has several keys named retention_period; only limits_config's
concern log retention, so the YAML is parsed rather than searched.
"""

from __future__ import annotations

from typing import Any

import yaml

from nis2scan.adapters._http import get_json, get_text
from nis2scan.adapters.logging import LogAdapter, LogRetentionEvidence, LogScope, adapter, days
from nis2scan.config import LogsTarget
from nis2scan.registry import CollectorError


@adapter
class Loki(LogAdapter):
    product = "loki"
    label = "Grafana Loki"
    access = "Read access to Loki's /config endpoint (no credentials unless a proxy requires them)"

    def recognise(self, logs: LogsTarget, secret) -> str | None:
        if not logs.url:
            return None
        try:
            info = get_json(f"{logs.url.rstrip('/')}/loki/api/v1/status/buildinfo")
        except CollectorError:
            return None
        if isinstance(info, dict) and "version" in info and "goVersion" in info:
            return f"build-info endpoint (Loki {info['version']})"
        return None

    def check_access(self, logs: LogsTarget, secret) -> None:
        get_text(f"{logs.url.rstrip('/')}/config")

    def fetch(self, logs: LogsTarget, secret) -> dict[str, Any]:
        config = yaml.safe_load(get_text(f"{logs.url.rstrip('/')}/config"))
        limits = config["limits_config"]
        return {
            "source": f"{logs.url.rstrip('/')}/config",
            "limits_config": {
                "retention_period": limits["retention_period"],
                "retention_stream": limits.get("retention_stream") or [],
            },
            "compactor": {"retention_enabled": config["compactor"]["retention_enabled"]},
        }

    def normalize(self, raw: dict[str, Any]) -> LogRetentionEvidence:
        limits = raw["limits_config"]
        if not raw["compactor"]["retention_enabled"]:
            scopes = [
                LogScope(
                    name="all streams", retention_days=None, source="compactor retention disabled"
                )
            ]
        else:
            scopes = [
                LogScope(
                    name="all streams",
                    retention_days=days(limits["retention_period"]) or None,  # 0: never delete
                    source=f"limits_config.retention_period {limits['retention_period']}",
                )
            ] + [
                LogScope(
                    name=f"streams {s['selector']}",
                    retention_days=days(s["period"]) or None,
                    source=f"limits_config.retention_stream {s['period']}",
                )
                for s in limits.get("retention_stream") or []
            ]
        return LogRetentionEvidence(store=raw["source"], scopes=scopes)
