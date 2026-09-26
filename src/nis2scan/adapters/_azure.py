"""Microsoft Entra sign-in for app registrations, shared by the Azure-based adapters."""

from __future__ import annotations

from typing import Any

from nis2scan.adapters._http import get_json, request

GRAPH_SCOPE = "https://graph.microsoft.com/.default"
ARM_SCOPE = "https://management.azure.com/.default"  # Azure Resource Manager


def client_credentials_token(tenant: str, client_id: str, client_secret: str, scope: str) -> str:
    """An access token for an app registration (OAuth 2.0 client credentials)."""
    body, _ = request(
        f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,
        },
    )
    return body["access_token"]


def get_all(url: str, headers: dict[str, str], limit: int = 10_000) -> list[Any]:
    """Follow Azure Resource Manager's `nextLink` paging and join the pages' `value`."""
    items: list[Any] = []
    while url and len(items) < limit:
        page = get_json(url, headers)
        items.extend(page.get("value", []))
        url = page.get("nextLink", "")
    return items
