"""AWS Backup and Azure Backup adapters, against documented API responses."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from nis2scan.adapters import _azure
from nis2scan.adapters.backup import ADAPTERS
from nis2scan.adapters.backup import aws as aws_module
from nis2scan.adapters.backup import azure as azure_module
from nis2scan.checks.operations import backups_encrypted, recent_backup
from nis2scan.config import BackupTarget, load_profile
from nis2scan.registry import CollectorError

FIXTURES = Path(__file__).parent / "fixtures"
PROFILE = load_profile(Path(__file__).parent.parent / "catalog" / "profile.yaml")
NOW = datetime(2026, 9, 26, 12, tzinfo=UTC)
AWS = json.loads((FIXTURES / "aws" / "documented.json").read_text())
AZURE = json.loads((FIXTURES / "azure" / "documented.json").read_text())


def checks(evidence):
    ev = {"backup": evidence.model_dump(mode="json")}
    return recent_backup(ev, PROFILE, NOW), backups_encrypted(ev, PROFILE, NOW)


# --- AWS Backup -----------------------------------------------------------------------

AWS_TARGET = BackupTarget(
    region="eu-north-1", access_key_id_env="AWS_KEY", secret_access_key_env="AWS_SECRET"
)


@pytest.fixture
def fake_aws(monkeypatch):
    calls = []

    def fake_run(backup, argv, env, secret, timeout=120):
        calls.append((argv, env))
        if argv[:2] == ["aws", "--version"]:
            return "aws-cli/2.31.4 Python/3.13.7 Linux/6.18 exe/x86_64\n"
        command = argv[2]
        if command == "list-backup-vaults":
            return json.dumps(AWS["list-backup-vaults"])
        return json.dumps(AWS[argv[argv.index("--backup-vault-name") + 1]])

    monkeypatch.setattr(aws_module, "run", fake_run)
    return calls


def secrets(name):
    return {"AWS_KEY": "AKIA-test", "AWS_SECRET": "secret-test", "AZ_SECRET": "az-secret"}[name]


def test_aws_resources_become_sets(fake_aws):
    repo = ADAPTERS["aws-backup"].normalize(ADAPTERS["aws-backup"].fetch(AWS_TARGET, secrets))
    sets = {s.name: s for s in repo.sets}
    assert set(sets) == {"EBS volume/vol-0web", "EBS volume/vol-0legacy", "RDS db:orders"}
    # A PARTIAL or EXPIRED recovery point is not a backup.
    assert sets["EBS volume/vol-0web"].newest.time == datetime(
        2026, 9, 25, 1, 0, 12, 345000, tzinfo=UTC
    )
    assert len(sets["RDS db:orders"].snapshots) == 1
    assert sets["EBS volume/vol-0legacy"].encrypted is False


def test_aws_checks_name_the_problem_resources(fake_aws):
    age, encryption = checks(
        ADAPTERS["aws-backup"].normalize(ADAPTERS["aws-backup"].fetch(AWS_TARGET, secrets))
    )
    assert age.status == "fail" and age.message.endswith("(RDS db:orders)")
    assert encryption.observed["unencrypted_sets"] == ["EBS volume/vol-0legacy"]


def test_aws_credentials_travel_in_the_environment(fake_aws):
    ADAPTERS["aws-backup"].fetch(AWS_TARGET, secrets)
    _argv, env = fake_aws[0]
    assert env["AWS_ACCESS_KEY_ID"] == "AKIA-test" and env["AWS_SECRET_ACCESS_KEY"] == "secret-test"
    assert env["AWS_DEFAULT_REGION"] == "eu-north-1"
    assert not any("secret-test" in part for call, _ in fake_aws for part in call)


def test_aws_profile_instead_of_keys(fake_aws):
    ADAPTERS["aws-backup"].check_access(
        BackupTarget(region="eu-north-1", aws_profile="audit"), secrets
    )
    _, env = fake_aws[0]
    assert env["AWS_PROFILE"] == "audit" and "AWS_ACCESS_KEY_ID" not in env


def test_aws_is_recognised_by_region_and_cli(fake_aws):
    assert (
        ADAPTERS["aws-backup"].recognise(AWS_TARGET, secrets)
        == "aws-cli/2.31.4 for region eu-north-1"
    )
    assert ADAPTERS["aws-backup"].recognise(BackupTarget(container="c"), secrets) is None


def test_aws_cannot_run_in_a_container():
    with pytest.raises(CollectorError, match="AWS CLI on the scanning host"):
        ADAPTERS["aws-backup"].fetch(BackupTarget(container="c", region="eu-north-1"), secrets)


# --- Azure Backup ---------------------------------------------------------------------

AZ_TARGET = BackupTarget(
    subscription="00000000-0000-0000-0000-00000000aaaa",
    tenant="contoso.onmicrosoft.com",
    client_id="11111111-2222-3333-4444-555555555555",
    client_secret_env="AZ_SECRET",
)


@pytest.fixture
def fake_azure(monkeypatch):
    calls = []

    def token(tenant, client_id, secret, scope):
        calls.append(("token", tenant, client_id, secret, scope))
        return "arm-token"

    def get_json(url, headers=None, context=None):
        assert headers == {"Authorization": "Bearer arm-token"}
        calls.append(("GET", url))
        if "/providers/Microsoft.RecoveryServices/vaults?" in url:
            # The first page carries a nextLink to the second.
            if "page=2" in url:
                return {"value": AZURE["vaults"][1:]}
            return {"value": AZURE["vaults"][:1], "nextLink": url + "&page=2"}
        if "/backupProtectedItems" in url:
            vault = url.split("/vaults/")[1].split("/")[0]
            return {"value": AZURE["items"][vault]}
        return AZURE["subscription"]

    monkeypatch.setattr(azure_module, "client_credentials_token", token)
    monkeypatch.setattr(azure_module, "get_json", get_json)
    monkeypatch.setattr(_azure, "get_json", get_json)
    return calls


def test_azure_items_become_sets(fake_azure):
    repo = ADAPTERS["azure-backup"].normalize(ADAPTERS["azure-backup"].fetch(AZ_TARGET, secrets))
    sets = {s.name: s for s in repo.sets}
    assert set(sets) == {
        "rsv-prod/vm-app01",
        "rsv-prod/vm-legacy",
        "rsv-files/share-docs",
        "rsv-files/share-hr",
    }
    assert sets["rsv-prod/vm-app01"].newest.time == datetime(
        2026, 9, 26, 0, 31, 16, 725421, tzinfo=UTC
    )
    # File shares report no lastRecoveryPoint; a completed lastBackupTime counts...
    assert sets["rsv-files/share-docs"].newest.time == datetime(2026, 9, 25, 22, tzinfo=UTC)
    # ...a failed one does not.
    assert sets["rsv-files/share-hr"].snapshots == []
    assert all(s.encrypted for s in repo.sets)


def test_azure_checks(fake_azure):
    age, encryption = checks(
        ADAPTERS["azure-backup"].normalize(ADAPTERS["azure-backup"].fetch(AZ_TARGET, secrets))
    )
    assert (age.status, age.message) == ("fail", "No backup snapshots exist (rsv-files/share-hr)")
    assert encryption.status == "pass"


def test_azure_signs_in_for_resource_manager(fake_azure):
    ADAPTERS["azure-backup"].check_access(AZ_TARGET, secrets)
    assert fake_azure[0] == (
        "token",
        "contoso.onmicrosoft.com",
        "11111111-2222-3333-4444-555555555555",
        "az-secret",
        "https://management.azure.com/.default",
    )


def test_azure_is_recognised_by_its_subscription(fake_azure):
    assert (
        ADAPTERS["azure-backup"].recognise(AZ_TARGET, secrets)
        == "Azure subscription Contoso production"
    )


def test_azure_needs_its_settings():
    with pytest.raises(
        CollectorError, match="needs subscription, tenant, client_id and client_secret_env"
    ):
        ADAPTERS["azure-backup"].fetch(BackupTarget(subscription="x"), secrets)
