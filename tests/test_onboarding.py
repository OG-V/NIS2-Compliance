"""Onboarding: the access each system needs and whether it is in place, without a network."""

from datetime import date

import pytest
import yaml
from conftest import ROOT

from nis2scan import onboarding as ob
from nis2scan.adapters.identity import ADAPTERS
from nis2scan.adapters.identity.detect import Detection
from nis2scan.config import load_target
from nis2scan.registry import CollectorError


@pytest.fixture
def lab(tmp_path, monkeypatch):
    """The lab target, with its documents and secrets but no live systems."""
    raw = yaml.safe_load((ROOT / "lab" / "target.yaml").read_text())
    raw["env_file"] = str(tmp_path / "lab.env")
    raw["documents"]["dir"] = str(ROOT / "lab" / "profiles" / "hardened" / "org")
    (tmp_path / "lab.env").write_text("KC_ADMIN_PASSWORD=not-a-real-password\n")
    path = tmp_path / "target.yaml"
    path.write_text(yaml.safe_dump(raw))
    monkeypatch.setattr(ob, "reachable", lambda host, port, timeout=3.0: True)
    monkeypatch.setattr(ob, "container_exists", lambda name: True)
    monkeypatch.setattr(ob, "compose_project_running", lambda project: True)
    monkeypatch.setattr(
        ob, "detect", lambda idp: Detection("keycloak", "OpenID configuration", "issuer x")
    )
    monkeypatch.setattr(ADAPTERS["keycloak"], "check_access", lambda idp, secret: None)
    stores = {"loki": "loki", "elasticsearch": "elasticsearch"}
    monkeypatch.setattr(
        ob,
        "log_detect",
        lambda logs: {"product": stores[logs.name], "method": "test", "detail": ""},
    )
    for adapter in ob.LOG_ADAPTERS.values():
        monkeypatch.setattr(adapter, "check_access", lambda logs, secret: None)
    return load_target(path)


def by_name(systems):
    return {s.name: s for s in systems}


def test_everything_in_place(lab):
    systems = by_name(ob.plan(lab))
    assert all(s.ready for s in systems.values())
    idp = systems["keycloak"]
    assert idp.product == "Keycloak" and idp.identified_by.startswith("identified from its OpenID")
    assert idp.access[1].note == "tested with one read-only request"
    assert ob.authorisation(lab, date(2026, 9, 25)).status == ob.OK


def test_unreachable_and_refused_access_are_reported(lab, monkeypatch):
    monkeypatch.setattr(ob, "reachable", lambda host, port, timeout=3.0: port != 18443)

    def refuse(idp, secret):
        raise CollectorError("admin login failed with HTTP 401")

    monkeypatch.setattr(ADAPTERS["keycloak"], "check_access", refuse)
    systems = by_name(ob.plan(lab))
    assert not systems["portal"].ready
    assert [a.status for a in systems["portal"].access] == [ob.MISSING, ob.OK]
    credential = systems["keycloak"].access[1]
    assert (credential.status, credential.note) == (
        ob.MISSING,
        "refused: admin login failed with HTTP 401",
    )


def test_missing_secret_is_named_but_never_shown(lab, monkeypatch):
    lab._env = {}
    monkeypatch.delenv("KC_ADMIN_PASSWORD", raising=False)
    credential = by_name(ob.plan(lab))["keycloak"].access[1]
    assert (credential.status, credential.note) == (
        ob.MISSING,
        "secret KC_ADMIN_PASSWORD is not set",
    )


def test_ssh_without_config_access_is_optional(lab):
    lab.ssh[0].container = None
    ssh = by_name(ob.plan(lab))["app-host"]
    assert ssh.ready and ssh.access[1].status == ob.OPTIONAL


def test_unsupported_identity_product_is_named(lab, monkeypatch):
    monkeypatch.setattr(ob, "detect", lambda idp: Detection("google", "OpenID configuration", ""))
    idp = by_name(ob.plan(lab))["keycloak"]
    assert idp.product == "Google" and not idp.ready
    assert idp.access[-1].note == "no adapter for this product yet"


def test_without_probing_nothing_is_contacted(lab, monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("probed")

    for name in ("reachable", "container_exists", "compose_project_running", "detect"):
        monkeypatch.setattr(ob, name, fail)
    systems = ob.plan(lab, probe=False)
    assert {a.status for s in systems for a in s.access} >= {ob.UNVERIFIED}
    assert by_name(systems)["documents"].ready  # local files are still checked


@pytest.mark.parametrize(
    "engagement, day, status",
    [
        (None, date(2026, 9, 25), ob.MISSING),
        ("lab", date(2026, 9, 25), ob.OK),
        ("lab", date(2028, 1, 1), ob.MISSING),
    ],
)
def test_authorisation(lab, engagement, day, status):
    if engagement is None:
        lab.engagement = None
    assert ob.authorisation(lab, day).status == status


def test_checklist_for_the_client(lab):
    text = ob.checklist_markdown(lab, ob.plan(lab), ob.authorisation(lab, date(2026, 9, 25)))
    assert text.startswith("# Access checklist: nordmsp-lab")
    assert "- [x] A Keycloak admin account for the realm" in text
    assert "not-a-real-password" not in text
