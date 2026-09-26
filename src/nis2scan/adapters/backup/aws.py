"""AWS Backup: recovery points in every backup vault of a region, via the AWS CLI.

Runs `aws backup list-backup-vaults` and `aws backup list-recovery-points-by-backup-vault`
on the scanning host (the CLI follows the pages itself). Credentials come from a named
CLI profile, or from access keys in the target's secrets, passed in the environment.
The IAM identity needs only backup:ListBackupVaults and
backup:ListRecoveryPointsByBackupVault.

Each protected resource is a backup set: its newest COMPLETED recovery point decides
its age, and that point's IsEncrypted its encryption. Partial, expired or deleting
points do not count as backups.
Verified against a live account (an on-demand DynamoDB backup). The CLI prints times in
the scanning host's local zone with its offset; the instant is what is compared.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from nis2scan.adapters.backup import (
    BackupAdapter,
    BackupEvidence,
    BackupSet,
    Snapshot,
    adapter,
    run,
)
from nis2scan.config import BackupTarget
from nis2scan.registry import CollectorError


def _env(backup: BackupTarget, secret) -> dict[str, str]:
    env = {"AWS_DEFAULT_REGION": backup.region or "", "AWS_PAGER": ""}
    if backup.aws_profile:
        env["AWS_PROFILE"] = backup.aws_profile
    elif backup.access_key_id_env and backup.secret_access_key_env:
        env["AWS_ACCESS_KEY_ID"] = secret(backup.access_key_id_env)
        env["AWS_SECRET_ACCESS_KEY"] = secret(backup.secret_access_key_env)
    return env


def _aws(backup: BackupTarget, secret, *args: str) -> Any:
    if backup.container:
        raise CollectorError(
            "AWS Backup is read with the AWS CLI on the scanning host, not in a container"
        )
    out = run(backup, ["aws", "backup", *args, "--output", "json"], _env(backup, secret), secret)
    return json.loads(out)


def resource_name(arn: str) -> str:
    """'arn:aws:ec2:eu-north-1:123:volume/vol-0abc' -> 'volume/vol-0abc'."""
    return arn.split(":", 5)[-1] if arn.count(":") >= 5 else arn


@adapter
class AwsBackup(BackupAdapter):
    product = "aws-backup"
    label = "AWS Backup"
    access = (
        "An AWS IAM identity allowed only backup:ListBackupVaults and "
        "backup:ListRecoveryPointsByBackupVault, as a CLI profile or an access key"
    )

    def recognise(self, backup: BackupTarget, secret) -> str | None:
        if not backup.region:
            return None
        try:
            out = run(backup, ["aws", "--version"], _env(backup, secret), secret, timeout=30)
        except CollectorError:
            return None
        return (
            f"{out.split()[0]} for region {backup.region}" if out.startswith("aws-cli/") else None
        )

    def check_access(self, backup: BackupTarget, secret) -> None:
        _aws(backup, secret, "list-backup-vaults")

    def fetch(self, backup: BackupTarget, secret) -> dict[str, Any]:
        vaults = _aws(backup, secret, "list-backup-vaults").get("BackupVaultList", [])
        points = []
        for vault in vaults:
            listing = _aws(
                backup,
                secret,
                "list-recovery-points-by-backup-vault",
                "--backup-vault-name",
                vault["BackupVaultName"],
            )
            points += [
                {
                    k: p.get(k)
                    for k in (
                        "BackupVaultName",
                        "ResourceArn",
                        "ResourceType",
                        "CreationDate",
                        "Status",
                        "IsEncrypted",
                    )
                }
                for p in listing.get("RecoveryPoints", [])
            ]
        return {
            "region": backup.region,
            "vaults": [v["BackupVaultName"] for v in vaults],
            "recovery_points": points,
        }

    def normalize(self, raw: dict[str, Any]) -> BackupEvidence:
        by_resource: dict[str, list[dict]] = {}
        for p in raw["recovery_points"]:
            by_resource.setdefault(p["ResourceArn"], []).append(p)
        sets = []
        for arn, points in sorted(by_resource.items()):
            done = [p for p in points if p.get("Status") == "COMPLETED"]
            newest = max(done, key=lambda p: p["CreationDate"]) if done else None
            sets.append(
                BackupSet(
                    name=f"{points[0].get('ResourceType', '?')} {resource_name(arn)}",
                    snapshots=[
                        Snapshot(
                            time=datetime.fromisoformat(p["CreationDate"]),
                            name=p["BackupVaultName"],
                        )
                        for p in done
                    ],
                    encrypted=None if newest is None else newest.get("IsEncrypted"),
                )
            )
        return BackupEvidence(repository=f"AWS Backup in {raw['region']}", sets=sets)
