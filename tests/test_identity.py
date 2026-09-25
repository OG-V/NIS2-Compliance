"""Identity adapters and detection, against recorded and documented API responses."""

import copy
import json
from pathlib import Path

import pytest
from conftest import FIXTURES

from nis2scan.adapters import _http
from nis2scan.adapters.identity import ADAPTERS, entra
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
        lambda url: {"issuer": "https://accounts.google.com"},
    )
    with pytest.raises(CollectorError, match="Google detected .* not supported yet"):
        detect(IdpTarget(url="https://accounts.google.com"))


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


# --- Okta sign-in policies (recorded from a live Identity Engine org) --------------

LIVE = json.loads((Path(__file__).parent / "fixtures" / "okta" / "live-oie-dev.json").read_text())


def _access_rule(raw, policy_name):
    policy = next(p for p in raw["access_policies"] if p["name"] == policy_name)
    return next(r for r in policy["rules"] if r["name"] == "Catch-all Rule")


def test_live_org_has_one_password_only_app():
    idp = ADAPTERS["okta"].normalize(LIVE)
    assert idp.users_without_mfa == []
    # Every other app requires 2FA. The password-expiry rule (an expression condition)
    # and account management ("2FA_If_Possible") are not sign-in paths.
    assert idp.password_only_sign_in == ["Okta OIN Submission Tester"]
    assert not idp.new_users_must_enrol_mfa  # that app can be used without ever enrolling


def test_all_apps_requiring_2fa_forces_enrolment():
    raw = copy.deepcopy(LIVE)
    rule = _access_rule(raw, "Okta OIN Submission Tester")
    rule["actions"]["appSignOn"]["verificationMethod"]["factorMode"] = "2FA"
    idp = ADAPTERS["okta"].normalize(raw)
    assert idp.password_only_sign_in == []
    assert idp.new_users_must_enrol_mfa  # Okta Verify is optional, so it can be enrolled


def test_no_enrollable_factor_means_no_forced_enrolment():
    raw = copy.deepcopy(LIVE)
    _access_rule(raw, "Okta OIN Submission Tester")["actions"]["appSignOn"]["verificationMethod"][
        "factorMode"
    ] = "2FA"
    for a in raw["mfa_enroll_policies"][0]["settings"]["authenticators"]:
        a["enroll"]["self"] = "NOT_ALLOWED" if a["key"] != "okta_password" else "REQUIRED"
    assert not ADAPTERS["okta"].normalize(raw).new_users_must_enrol_mfa


def test_session_policy_requiring_a_factor_covers_every_app():
    raw = copy.deepcopy(LIVE)
    for p in raw["sign_on_policies"]:
        for r in p["rules"]:
            r["actions"]["signon"]["requireFactor"] = True
    assert ADAPTERS["okta"].normalize(raw).password_only_sign_in == []


def test_classic_engine_relies_on_the_session_policy():
    raw = copy.deepcopy(LIVE)
    raw["access_policies"] = None  # Classic Engine orgs have no authentication policies
    assert ADAPTERS["okta"].normalize(raw).password_only_sign_in == ["Default Policy"]


def test_evidence_without_sign_in_policies_says_nothing_about_them():
    assert ADAPTERS["okta"].normalize(OKTA).password_only_sign_in is None


def test_mfa_check_names_password_only_apps():
    from nis2scan.checks.identity import mfa_enforced

    ev = {"identity": ADAPTERS["okta"].normalize(LIVE).model_dump()}
    result = mfa_enforced(ev, None, None)
    assert result.status == "fail"
    assert result.message == (
        "New accounts are not required to enrol a second factor; "
        "a password alone signs in through Okta OIN Submission Tester"
    )
    assert result.observed["password_only_sign_in"] == ["Okta OIN Submission Tester"]


# --- Microsoft Entra ID (documented response shapes) --------------------------------


ENTRA = json.loads((Path(__file__).parent / "fixtures" / "entra" / "documented.json").read_text())


def test_entra_users_and_methods():
    idp = ADAPTERS["entra-id"].normalize(ENTRA)
    assert idp.tenant == "Contoso"
    external = [u.username for u in idp.users if u.external]
    assert external == ["partner_fabrikam.example#EXT#@contoso.example"]  # signs in at home
    # Email is not a second factor; a disabled account cannot sign in.
    assert idp.users_without_mfa == ["sales@contoso.example"]


def test_entra_fixed_password_rules_and_smart_lockout():
    idp = ADAPTERS["entra-id"].normalize(ENTRA)
    assert idp.password_min_length == 8
    assert idp.lockout_enabled and idp.lockout_max_attempts == 10
    assert "fixed by Microsoft" in idp.password_policy
    custom = {**ENTRA, "password_rule_settings": {"LockoutThreshold": "5"}}
    assert ADAPTERS["entra-id"].normalize(custom).lockout_max_attempts == 5


def test_entra_conditional_access_exclusions_are_reported():
    idp = ADAPTERS["entra-id"].normalize(ENTRA)
    assert idp.password_only_sign_in == [
        (
            "Microsoft Entra ID sign-in for the 1 users, groups or roles excluded from "
            "Conditional Access policy 'Require MFA for all users'"
        )
    ]
    assert not idp.new_users_must_enrol_mfa


def test_entra_policy_without_exclusions_enforces_mfa():
    raw = copy.deepcopy(ENTRA)
    raw["conditional_access_policies"][0]["conditions"]["users"]["excludeUsers"] = []
    idp = ADAPTERS["entra-id"].normalize(raw)
    assert idp.password_only_sign_in == [] and idp.new_users_must_enrol_mfa


def test_entra_report_only_policies_do_not_count():
    raw = copy.deepcopy(ENTRA)
    raw["conditional_access_policies"][0]["state"] = "enabledForReportingButNotEnforced"
    assert ADAPTERS["entra-id"].normalize(raw).password_only_sign_in == [
        (
            "Microsoft Entra ID sign-in (security defaults are off and no enabled Conditional "
            "Access policy requires MFA for all users and apps)"
        )
    ]


def test_entra_security_defaults_enforce_mfa():
    raw = {**ENTRA, "security_defaults_enabled": True, "conditional_access_policies": None}
    idp = ADAPTERS["entra-id"].normalize(raw)
    assert idp.password_only_sign_in == [] and idp.new_users_must_enrol_mfa


def test_entra_without_conditional_access_licence():
    raw = {**ENTRA, "conditional_access_policies": None}
    (only,) = ADAPTERS["entra-id"].normalize(raw).password_only_sign_in
    assert "Conditional Access is not available in this tenant" in only


def test_entra_authentication_strength_counts_as_mfa():
    policy = copy.deepcopy(ENTRA["conditional_access_policies"][0])
    policy["grantControls"] = {"builtInControls": [], "authenticationStrength": {"id": "x"}}
    assert entra.enforces_mfa_for_everyone(policy)


def test_entra_tenant_and_method_names():
    assert entra.tenant_of(IdpTarget(url="https://login.microsoftonline.com/abc-123")) == "abc-123"
    with pytest.raises(CollectorError, match="must include the tenant"):
        entra.tenant_of(IdpTarget(url="https://login.microsoftonline.com/"))
    assert (
        entra.method_type({"@odata.type": "#microsoft.graph.fido2AuthenticationMethod"}) == "fido2"
    )


def test_entra_discovery_url_is_per_tenant():
    from nis2scan.adapters.identity.detect import discovery_urls

    urls = discovery_urls(IdpTarget(url="https://login.microsoftonline.com/abc-123"))
    assert (
        urls[0] == "https://login.microsoftonline.com/abc-123/v2.0/.well-known/openid-configuration"
    )


ENTRA_LIVE = json.loads(
    (Path(__file__).parent / "fixtures" / "entra" / "live-free-tenant.json").read_text()
)


def test_entra_live_free_tenant():
    idp = ADAPTERS["entra-id"].normalize(ENTRA_LIVE)
    # The tenant's creator is a personal Microsoft account: external, MFA at home.
    assert idp.users_without_mfa == [] and len(idp.external_accounts) == 1
    # Security defaults are on; Graph lists no Conditional Access policies.
    assert ENTRA_LIVE["conditional_access_policies"] == []
    assert idp.password_only_sign_in == [] and idp.new_users_must_enrol_mfa
    assert (idp.password_min_length, idp.lockout_max_attempts) == (8, 10)


def test_mfa_check_names_external_accounts():
    from nis2scan.checks.identity import mfa_enforced

    result = mfa_enforced(
        {"identity": ADAPTERS["entra-id"].normalize(ENTRA_LIVE).model_dump()}, None, None
    )
    assert result.status == "pass"
    assert (
        result.message
        == "No internal accounts; 1 external account(s) use their home provider's MFA"
    )
    assert result.observed["external_accounts"] == [
        "owner1_example.com#EXT#@example.onmicrosoft.com"
    ]


def test_fixed_password_minimum_is_explained():
    from nis2scan.checks.identity import password_length
    from nis2scan.config import load_profile
    from nis2scan.report.plain import explain

    ev = {"identity": ADAPTERS["entra-id"].normalize(ENTRA_LIVE).model_dump()}
    result = password_length(
        ev, load_profile(Path(__file__).parent.parent / "catalog" / "profile.yaml"), None
    )
    assert result.status == "fail" and result.observed["min_length_fixed_by_vendor"]
    plain = explain("CHK-IDP-003", result.observed, result.expected)
    assert "cannot be raised" in plain.found
    assert plain.action.startswith("Compensate for the fixed minimum") and plain.effort == "change"
