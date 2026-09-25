"""Recognise which identity provider a URL belongs to.

Every provider publishes an OpenID Connect configuration (RFC 8414 / OIDC Discovery).
Its `issuer` and endpoint URLs follow each product's own pattern, which identifies
the product without credentials. The adapter's authenticated fetch then confirms it.
"""

from __future__ import annotations

from urllib.parse import urlparse

from nis2scan.adapters._http import get_json
from nis2scan.adapters.identity import ADAPTERS, Detection
from nis2scan.config import IdpTarget
from nis2scan.registry import CollectorError

# Products we can recognise, including ones without an adapter yet, so the report can
# say "Microsoft Entra ID detected, not supported yet" rather than "unknown".
LABELS = {
    "keycloak": "Keycloak",
    "okta": "Okta",
    "entra-id": "Microsoft Entra ID",
    "google": "Google",
    "auth0": "Auth0",
}


def classify(config: dict) -> str | None:
    """The product an OpenID configuration belongs to, or None if unrecognised."""
    issuer = config.get("issuer", "")
    host = urlparse(issuer).hostname or ""
    authorize = config.get("authorization_endpoint", "")
    if "/realms/" in urlparse(issuer).path:
        return "keycloak"
    if (
        host.endswith(("okta.com", "oktapreview.com", "okta-emea.com"))
        or "/oauth2/v1/" in authorize
    ):
        return "okta"
    if host in ("login.microsoftonline.com", "sts.windows.net") or host.endswith(".ciamlogin.com"):
        return "entra-id"
    if host == "accounts.google.com":
        return "google"
    if host.endswith(".auth0.com"):
        return "auth0"
    return None


def discovery_urls(idp: IdpTarget) -> list[str]:
    base = idp.url.rstrip("/")
    urls = [f"{base}/.well-known/openid-configuration"]
    if urlparse(base).hostname == "login.microsoftonline.com":  # Entra ID: per tenant, v2.0
        urls.insert(0, f"{base}/v2.0/.well-known/openid-configuration")
    if idp.realm:  # Keycloak publishes per realm
        urls.insert(0, f"{base}/realms/{idp.realm}/.well-known/openid-configuration")
    return urls


def detect(idp: IdpTarget) -> Detection:
    if idp.product != "auto":
        if idp.product not in ADAPTERS:
            raise CollectorError(
                f"unknown identity product {idp.product!r}; supported: {', '.join(sorted(ADAPTERS))}"
            )
        return Detection(idp.product, "configured")
    tried = []
    for url in discovery_urls(idp):
        try:
            config = get_json(url)
        except CollectorError as exc:
            tried.append(f"{url} ({exc})")
            continue
        product = classify(config)
        if product is None:
            tried.append(f"{url} (issuer {config.get('issuer')!r} not recognised)")
            continue
        if product not in ADAPTERS:
            raise CollectorError(
                f"{LABELS[product]} detected at {idp.url}; it is not supported yet"
            )
        return Detection(product, "OpenID configuration", f"issuer {config.get('issuer')}")
    raise CollectorError(
        "could not recognise the identity provider; set `product:` in the target. Tried: "
        + "; ".join(tried)
    )
