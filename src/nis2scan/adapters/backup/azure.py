"""Azure Backup: protected items in every Recovery Services vault of a subscription.

Uses Azure Resource Manager with an Entra app registration (client credentials) that
has the Backup Reader role on the subscription:
- GET /subscriptions/{id}                                           recognition
- GET /subscriptions/{id}/providers/Microsoft.RecoveryServices/vaults
- GET {vault id}/backupProtectedItems                               per vault

Each protected item (a VM, a file share, a database) is a backup set. Its latest
recovery point decides its age: `lastRecoveryPoint` where the item type reports it,
otherwise `lastBackupTime` unless the last backup failed. Azure Backup always encrypts
backup data at rest (with platform-managed or customer-managed keys), so every set is
encrypted; the vault's key setting is kept in the evidence.
Built from the Azure REST API reference; see the design doc for its verification.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from nis2scan.adapters._azure import ARM_SCOPE, client_credentials_token, get_all
from nis2scan.adapters._http import get_json
from nis2scan.adapters.backup import BackupAdapter, BackupEvidence, BackupSet, Snapshot, adapter
from nis2scan.config import BackupTarget
from nis2scan.registry import CollectorError

ARM = "https://management.azure.com"
VAULTS_API = "2023-04-01"
ITEMS_API = "2023-04-01"
SUBSCRIPTION_API = "2022-12-01"


def _headers(backup: BackupTarget, secret) -> dict[str, str]:
    if not (
        backup.subscription and backup.tenant and backup.client_id and backup.client_secret_env
    ):
        raise CollectorError(
            "Azure Backup needs subscription, tenant, client_id and client_secret_env set"
        )
    token = client_credentials_token(
        backup.tenant, backup.client_id, secret(backup.client_secret_env), ARM_SCOPE
    )
    return {"Authorization": f"Bearer {token}"}


def latest_recovery_point(item: dict) -> str | None:
    props = item.get("properties") or {}
    if props.get("lastRecoveryPoint"):
        return props["lastRecoveryPoint"]
    if props.get("lastBackupTime") and props.get("lastBackupStatus") not in ("Failed", "Unhealthy"):
        return props["lastBackupTime"]
    return None


def parse_time(text: str) -> datetime:
    time = datetime.fromisoformat(text)
    return time if time.tzinfo else time.replace(tzinfo=UTC)  # ARM times are UTC


@adapter
class AzureBackup(BackupAdapter):
    product = "azure-backup"
    label = "Azure Backup"
    access = (
        "A Microsoft Entra app registration with a client secret, holding the Azure role "
        "Backup Reader on the subscription"
    )

    def recognise(self, backup: BackupTarget, secret) -> str | None:
        if not backup.subscription:
            return None
        try:
            sub = get_json(
                f"{ARM}/subscriptions/{backup.subscription}?api-version={SUBSCRIPTION_API}",
                _headers(backup, secret),
            )
        except CollectorError:
            return None
        return f"subscription '{sub.get('displayName', backup.subscription)}' reachable in Azure"

    def check_access(self, backup: BackupTarget, secret) -> None:
        self._vaults(backup, _headers(backup, secret))

    def _vaults(self, backup: BackupTarget, headers: dict) -> list[dict]:
        return get_all(
            f"{ARM}/subscriptions/{backup.subscription}/providers/"
            f"Microsoft.RecoveryServices/vaults?api-version={VAULTS_API}",
            headers,
        )

    def fetch(self, backup: BackupTarget, secret) -> dict[str, Any]:
        headers = _headers(backup, secret)
        vaults = []
        for vault in self._vaults(backup, headers):
            items = get_all(
                f"{ARM}{vault['id']}/backupProtectedItems?api-version={ITEMS_API}", headers
            )
            vaults.append(
                {
                    "name": vault["name"],
                    "location": vault.get("location"),
                    "encryption": (vault.get("properties") or {}).get("encryption"),
                    "items": [
                        {
                            "name": (i.get("properties") or {}).get("friendlyName")
                            or i.get("name"),
                            "type": (i.get("properties") or {}).get("protectedItemType"),
                            "protectionState": (i.get("properties") or {}).get("protectionState"),
                            "lastBackupStatus": (i.get("properties") or {}).get("lastBackupStatus"),
                            "latestRecoveryPoint": latest_recovery_point(i),
                        }
                        for i in items
                    ],
                }
            )
        return {"subscription": backup.subscription, "vaults": vaults}

    def normalize(self, raw: dict[str, Any]) -> BackupEvidence:
        sets = [
            BackupSet(
                name=f"{vault['name']}/{item['name']}",
                snapshots=(
                    [
                        Snapshot(
                            time=parse_time(item["latestRecoveryPoint"]), name=item["type"] or ""
                        )
                    ]
                    if item.get("latestRecoveryPoint")
                    else []
                ),
                encrypted=True,  # Azure Backup encrypts all backup data at rest
            )
            for vault in raw["vaults"]
            for item in vault["items"]
        ]
        return BackupEvidence(
            repository=f"Azure Backup in subscription {raw['subscription']}", sets=sets
        )
