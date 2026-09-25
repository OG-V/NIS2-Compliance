"""Identity adapters and detection, against recorded and documented API responses."""

import copy
import json
from pathlib import Path

import pytest
from conftest import FIXTURES

from nis2scan.adapters import _http
from nis2scan.adapters.identity import ADAPTERS
from nis2scan.adapters.identity.detect import classify, detect
from nis2scan.adapters.identity.okta import requires_second_factor
from nis2scan.collectors.identity import idp_config, idp_default_admin
from nis2scan.config import IdpTarget, Target
from nis2scan.registry import CollectorError, NotApplicable

OKTA = json.loads((Path(__file__).parent / "fixtures" / "okta" / "documented.json").read_text())


# --- Keycloak ----------------------------------------------------------------------


@pytest.mark.parametrize("profile", ["weak", "hardened"])
def test_keycloak_evidence_is_the_normalised_raw_response(profile):
    """The recorded evidence must be exactly what the adapter makes of its raw part."""
    ev = json.loads((FIXTURES / profile / "idp_config.json").read_text())
    assert ADAPTERS["keycloak"].normalize(ev["raw"]).model_dump() == ev["identity"]


def test_keycloak_normalisation():
    weak = json.loads((FIXTURES / "weak" / "idp_config.json").read_text())["identity"]
    hardened = json.loads((FIXTURES / "hardened" / "idp_config.json").read_text())["identity"]
    assert (weak["lockout_enabled"], weak["password_min_length"]) == (False, 0)
    assert (hardened["lockout_max_attempts"], hardened["password_min_length"]) == (5, 12)
    # Hardened users have no factor yet but must enrol one at their next login.
    assert all(u["mfa_pending"] and not u["mfa_enrolled"] for u in hardened["users"])


# --- Okta --------------------------------------------------------------------------


def test_okta_normalisation():
    idp = ADAPTERS["okta"].normalize(OKTA)
    assert idp.tenant == "dev-00000000.okta.com"
    enrolled = {u.username: u.mfa_enrolled for u in idp.users}
    assert enrolled["anna.admin@example.com"]  # push counts
    assert not enrolled["bo.ops@example.com"]  # email and security question do not
    assert not enrolled["cai.dev@example.com"]  # a factor still pending activation does not
    # Suspended and staged accounts cannot sign in, so they are not listed as lacking MFA.
    assert idp.users_without_mfa == ["bo.ops@example.com", "cai.dev@example.com"]
    # The weakest active policy decides; the inactive one is ignored.
    assert idp.password_min_length == 8
    assert idp.lockout_enabled and idp.lockout_max_attempts == 10
    assert "Default Policy: minimum length 8, lockout after 10" in idp.password_policy
    # Okta Verify is only optional in the default enrolment policy.
    assert not idp.new_users_must_enrol_mfa


def test_okta_one_policy_without_lockout_disables_lockout():
    raw = copy.deepcopy(OKTA)
    raw["password_policies"][1]["settings"]["password"]["lockout"]["maxAttempts"] = 0
    idp = ADAPTERS["okta"].normalize(raw)
    assert not idp.lockout_enabled and idp.lockout_max_attempts is None


@pytest.mark.parametrize(
    "settings, required",
    [
        ({"authenticators": [{"key": "okta_verify", "enroll": {"self": "REQUIRED"}}]}, True),
        ({"authenticators": [{"key": "okta_email", "enroll": {"self": "REQUIRED"}}]}, False),
        ({"factors": {"okta_otp": {"enroll": {"self": "REQUIRED"}}}}, True),  # Classic Engine
        ({"factors": {"okta_otp": {"enroll": {"self": "OPTIONAL"}}}}, False),
        ({}, False),
    ],
)
def test_okta_enrolment_policy(settings, required):
    assert requires_second_factor({"settings": settings}) is required


def test_okta_paging_follows_link_headers(monkeypatch):
    pages = {
        "https://o/api/v1/users?limit=2": (
            [1, 2],
            (
                '<https://o/api/v1/users?limit=2>; rel="self", '
                '<https://o/api/v1/users?after=2&limit=2>; rel="next"'
            ),
        ),
        "https://o/api/v1/users?after=2&limit=2": ([3], '<https://o/x>; rel="self"'),
    }

    class Headers:
        def __init__(self, link):
            self.link = link

        def get_all(self, name):
            return [self.link]

    monkeypatch.setattr(
        _http, "request", lambda url, headers=None: (pages[url][0], Headers(pages[url][1]))
    )
    assert _http.get_paged("https://o/api/v1/users?limit=2") == [1, 2, 3]


# --- detection ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "issuer, product",
    [
        ("http://127.0.0.1:18081/realms/nordmsp", "keycloak"),
        ("https://dev-12345678.okta.com", "okta"),
        ("https://acme.okta.com/oauth2/default", "okta"),
        ("https://login.microsoftonline.com/0000-tenant/v2.0", "entra-id"),
        ("https://accounts.google.com", "google"),
        ("https://acme.eu.auth0.com/", "auth0"),
        ("https://sso.example.org", None),
    ],
)
def test_classify_issuer(issuer, product):
    assert classify({"issuer": issuer}) == product


def test_okta_custom_domain_is_recognised_by_its_endpoints():
    config = {
        "issuer": "https://login.acme.com",
        "authorization_endpoint": "https://login.acme.com/oauth2/v1/authorize",
    }
    assert classify(config) == "okta"


def test_configured_product_skips_detection():
    d = detect(IdpTarget(url="https://x", product="okta"))
    assert (d.product, d.method) == ("okta", "configured")
    with pytest.raises(CollectorError, match="unknown identity product 'ping'"):
        detect(IdpTarget(url="https://x", product="ping"))


def test_recognised_but_unsupported_product(monkeypatch):
    from nis2scan.adapters.identity import detect as detect_module

    monkeypatch.setattr(
        detect_module,
        "get_json",
        lambda url: {"issuer": "https://login.microsoftonline.com/t/v2.0"},
    )
    with pytest.raises(CollectorError, match="Microsoft Entra ID detected .* not supported yet"):
        detect(IdpTarget(url="https://login.microsoftonline.com/t"))


# --- collectors --------------------------------------------------------------------


class DetectedAs:
    """A context whose detection result is fixed, for testing the collectors directly."""

    def __init__(self, product):
        self.target = Target(name="t")
        self.product = product

    def collect(self, name, asset):
        assert name == "idp_detect"
        return {"product": self.product}


def test_saas_products_have_no_default_login():
    with pytest.raises(NotApplicable, match="Okta has no default admin login"):
        idp_default_admin(DetectedAs("okta"), IdpTarget(url="https://x"))


def test_missing_product_settings_are_reported():
    with pytest.raises(CollectorError, match="Okta needs api_token_env set in the target"):
        idp_config(DetectedAs("okta"), IdpTarget(url="https://x"))
