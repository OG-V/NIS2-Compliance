"""Microsoft Sentinel: retention of the Log Analytics workspace behind it.

Sentinel stores its data in a Log Analytics workspace. The workspace sets a default
retention; each table can override it, and can add long-term (archive) retention on
top, during which logs can still be searched. Retention here is a table's total
retention: archived logs are kept, for an investigation, even if not interactively.

Uses Azure Resource Manager with an Entra app registration holding Log Analytics
Reader on the workspace (or subscription):
- GET /subscriptions/{id}/providers/Microsoft.OperationalInsights/workspaces
- GET {workspace}/providers/Microsoft.SecurityInsights/onboardingStates  (Sentinel on?)
- GET {workspace}/tables                                                 per-table retention
Without `workspace:` in the target, every workspace with Sentinel enabled is read.
Built from the Azure REST API reference.
"""

from __future__ import annotations

from typing import Any

from nis2scan.adapters._azure import ARM_SCOPE, client_credentials_token, get_all
from nis2scan.adapters._http import HttpError
from nis2scan.adapters.logging import LogAdapter, LogRetentionEvidence, LogScope, adapter
from nis2scan.config import LogsTarget
from nis2scan.registry import CollectorError

ARM = "https://management.azure.com"
WORKSPACES_API = "2023-09-01"
TABLES_API = "2022-10-01"
SENTINEL_API = "2024-03-01"


def _headers(logs: LogsTarget, secret) -> dict[str, str]:
    if not (logs.subscription and logs.tenant and logs.client_id and logs.client_secret_env):
        raise CollectorError(
            "Microsoft Sentinel needs subscription, tenant, client_id and client_secret_env set"
        )
    token = client_credentials_token(
        logs.tenant, logs.client_id, secret(logs.client_secret_env), ARM_SCOPE
    )
    return {"Authorization": f"Bearer {token}"}


def _workspaces(logs: LogsTarget, headers: dict) -> list[dict]:
    return get_all(
        f"{ARM}/subscriptions/{logs.subscription}/providers/"
        f"Microsoft.OperationalInsights/workspaces?api-version={WORKSPACES_API}",
        headers,
    )


def _sentinel_enabled(workspace: dict, headers: dict) -> bool:
    try:
        states = get_all(
            f"{ARM}{workspace['id']}/providers/Microsoft.SecurityInsights/"
            f"onboardingStates?api-version={SENTINEL_API}",
            headers,
        )
    except HttpError as exc:
        if exc.status in (400, 404):
            return False
        raise
    return bool(states)


def _on_default(table: dict) -> bool:
    return table.get("retentionInDaysAsDefault", True) and table.get(
        "totalRetentionInDaysAsDefault", True
    )


def _in_scope(logs: LogsTarget, headers: dict) -> list[dict]:
    """The named workspace, or every workspace with Sentinel enabled."""
    workspaces = _workspaces(logs, headers)
    if logs.workspace:
        named = [w for w in workspaces if w["name"] == logs.workspace]
        if not named:
            raise CollectorError(f"no workspace named {logs.workspace!r} in the subscription")
        return named
    return [w for w in workspaces if _sentinel_enabled(w, headers)]


@adapter
class Sentinel(LogAdapter):
    product = "sentinel"
    label = "Microsoft Sentinel"
    access = (
        "A Microsoft Entra app registration with a client secret, holding the Azure role "
        "Log Analytics Reader on the Sentinel workspace or its subscription"
    )

    def recognise(self, logs: LogsTarget, secret) -> str | None:
        if not logs.subscription:
            return None
        try:
            headers = _headers(logs, secret)
            names = [w["name"] for w in _workspaces(logs, headers) if _sentinel_enabled(w, headers)]
        except CollectorError:
            return None
        return f"Sentinel onboarding state (workspace {', '.join(names)})" if names else None

    def check_access(self, logs: LogsTarget, secret) -> None:
        _workspaces(logs, _headers(logs, secret))

    def fetch(self, logs: LogsTarget, secret) -> dict[str, Any]:
        headers = _headers(logs, secret)
        result = []
        for ws in _in_scope(logs, headers):
            tables = get_all(f"{ARM}{ws['id']}/tables?api-version={TABLES_API}", headers)
            # A workspace has hundreds of tables, nearly all on its default: record the
            # ones with their own settings, and how many follow the default.
            custom = [t for t in tables if not _on_default(t.get("properties") or {})]
            result.append(
                {
                    "name": ws["name"],
                    "retentionInDays": (ws.get("properties") or {}).get("retentionInDays"),
                    "sentinel": _sentinel_enabled(ws, headers),
                    "tables": {
                        t["name"]: {
                            k: (t.get("properties") or {}).get(k)
                            for k in (
                                "plan",
                                "retentionInDays",
                                "totalRetentionInDays",
                                "retentionInDaysAsDefault",
                                "totalRetentionInDaysAsDefault",
                            )
                        }
                        for t in custom
                    },
                    "tables_on_default": len(tables) - len(custom),
                }
            )
        return {"subscription": logs.subscription, "workspaces": result}

    def normalize(self, raw: dict[str, Any]) -> LogRetentionEvidence:
        scopes = []
        for ws in raw["workspaces"]:
            default = ws["retentionInDays"]
            scopes.append(
                LogScope(
                    name=f"workspace {ws['name']} (tables on its default)",
                    retention_days=default,
                    source=f"workspace retention {default} days",
                )
            )
            for name, t in sorted(ws["tables"].items()):
                if _on_default(t):
                    continue  # follows the workspace default above
                total = t.get("totalRetentionInDays") or t.get("retentionInDays")
                scopes.append(
                    LogScope(
                        name=f"table {ws['name']}/{name}",
                        retention_days=total,
                        source=(
                            f"table retention {t.get('retentionInDays')} days interactive, "
                            f"{total} days in total"
                        ),
                    )
                )
        if not scopes:
            raise ValueError("no Sentinel workspace found in the subscription")
        return LogRetentionEvidence(
            store=f"Microsoft Sentinel in subscription {raw['subscription']}", scopes=scopes
        )
