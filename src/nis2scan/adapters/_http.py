"""Small JSON-over-HTTP helpers for adapters, on the standard library only."""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
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


def normalise_fingerprint(text: str) -> str:
    """'AB:CD:…' or 'abcd…' -> 'abcd…' (SHA-256, lower-case hex)."""
    return text.replace(":", "").strip().lower()


def fingerprint(der: bytes) -> str:
    digest = hashlib.sha256(der).hexdigest().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def server_fingerprint(host: str, port: int) -> str:
    """The SHA-256 fingerprint of the certificate a server presents (for onboarding)."""
    pem = ssl.get_server_certificate((host, port), timeout=TIMEOUT)
    return fingerprint(ssl.PEM_cert_to_DER_cert(pem))


class _PinnedHandler(urllib.request.HTTPSHandler):
    """Accepts exactly one server certificate, checked on the connection that is used."""

    def __init__(self, pinned: str):
        context = ssl.create_default_context()
        context.check_hostname = False  # the pin replaces name and chain checks
        context.verify_mode = ssl.CERT_NONE
        super().__init__(context=context)
        self.pinned = pinned

    def https_open(self, req):
        pinned = self.pinned

        class Connection(http.client.HTTPSConnection):
            def connect(self):
                super().connect()
                presented = fingerprint(self.sock.getpeercert(binary_form=True))
                if normalise_fingerprint(presented) != pinned:
                    self.close()
                    raise ssl.SSLCertVerificationError(
                        f"server certificate {presented} is not the pinned one"
                    )

        return self.do_open(Connection, req, context=self._context)


@dataclass(frozen=True)
class Tls:
    """How to trust a server: an extra CA or certificate file, or one pinned certificate."""

    ca_file: str | None = None
    pinned: str | None = None  # SHA-256 fingerprint

    def open(self, req: urllib.request.Request):
        if self.pinned:
            opener = urllib.request.build_opener(_PinnedHandler(normalise_fingerprint(self.pinned)))
            return opener.open(req, timeout=TIMEOUT)
        return urllib.request.urlopen(
            req, timeout=TIMEOUT, context=ssl.create_default_context(cafile=self.ca_file)
        )


def request(
    url: str,
    headers: dict[str, str] | None = None,
    data: dict[str, str] | None = None,
    context: Tls | None = None,
) -> tuple[Any, Message]:
    """GET (or form-POST when `data` is given) a URL; return its JSON body and headers."""
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(
        url, data=body, headers={"Accept": "application/json", **(headers or {})}
    )
    try:
        opened = context.open(req) if context else urllib.request.urlopen(req, timeout=TIMEOUT)
        with opened as resp:
            return json.load(resp), resp.headers
    except urllib.error.HTTPError as exc:
        raise HttpError(url, exc.code, exc.read().decode(errors="replace"), exc.headers) from None
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CollectorError(f"cannot reach {url}: {exc}") from None


def get_json(url: str, headers: dict[str, str] | None = None, context: Tls | None = None) -> Any:
    return request(url, headers, context=context)[0]


def trust(ca_file=None, pinned: str | None = None) -> Tls | None:
    """How to trust a self-signed server: a certificate file, or a pinned fingerprint.

    Certificate checks are never switched off: without either, the system's CAs apply.
    """
    if not (ca_file or pinned):
        return None
    return Tls(str(ca_file) if ca_file else None, pinned)


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
