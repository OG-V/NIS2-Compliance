"""Small JSON-over-HTTP helpers for adapters, on the standard library only."""

from __future__ import annotations

import base64
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from email.message import Message
from typing import Any

from nis2scan.registry import CollectorError

TIMEOUT = 15


class HttpError(CollectorError):
    def __init__(self, url: str, status: int, body: str = "", headers: Message | None = None):
        super().__init__(f"HTTP {status} from {url}" + (f": {body[:200]}" if body else ""))
        self.status = status
        self.body = body
        self.headers = headers  # e.g. to recognise a product from its Server header


def basic_auth(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def get_text(url: str, headers: dict[str, str] | None = None) -> str:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read().decode()
    except urllib.error.HTTPError as exc:
        raise HttpError(url, exc.code, exc.read().decode(errors="replace")) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CollectorError(f"cannot reach {url}: {exc}") from None


def request(
    url: str,
    headers: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
    context: ssl.SSLContext | None = None,
) -> tuple[Any, Message]:
    """GET (or form-POST when `data` is given) a URL; return its JSON body and headers."""
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(
        url, data=body, headers={"Accept": "application/json", **(headers or {})}
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT, context=context) as resp:
            return json.load(resp), resp.headers
    except urllib.error.HTTPError as exc:
        raise HttpError(url, exc.code, exc.read().decode(errors="replace"), exc.headers) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CollectorError(f"cannot reach {url}: {exc}") from None


def get_json(
    url: str, headers: dict[str, str] | None = None, context: ssl.SSLContext | None = None
) -> Any:
    return request(url, headers, context=context)[0]


def trust(ca_file: str | None) -> ssl.SSLContext | None:
    """A TLS context that also trusts `ca_file` (e.g. a server's self-signed certificate)."""
    return ssl.create_default_context(cafile=ca_file) if ca_file else None


def get_paged(url: str, headers: dict[str, str] | None = None, limit: int = 10_000) -> list:
    """Follow RFC 8288 `Link: <...>; rel="next"` headers (as Okta does) and join the pages."""
    items: list = []
    while url and len(items) < limit:
        page, response_headers = request(url, headers)
        items.extend(page)
        # Okta sends one Link header per relation (self, next), so read them all.
        link = ", ".join(response_headers.get_all("Link") or [])
        match = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = match.group(1) if match else ""
    return items


def get_odata(url: str, headers: dict[str, str] | None = None, limit: int = 10_000) -> list:
    """Follow OData `@odata.nextLink` paging (as Microsoft Graph does) and join the pages."""
    items: list = []
    while url and len(items) < limit:
        page = get_json(url, headers)
        items.extend(page.get("value", []))
        url = page.get("@odata.nextLink", "")
    return items
