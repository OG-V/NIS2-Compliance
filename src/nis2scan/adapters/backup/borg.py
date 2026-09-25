"""BorgBackup: archives and the encryption mode from `borg list --json`.

Borg reports archive times in the local time of the machine that ran it, without a
time zone. They are read as UTC, which is what containers and most servers use; a
backup host on another zone would shift the age by that offset. The modes `none` and
`authenticated*` do not encrypt; the others (repokey, keyfile and their variants) do.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
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

NOT_ENCRYPTED = {"none", "authenticated", "authenticated-blake2"}


def _env(backup: BackupTarget) -> dict[str, str]:
    if not backup.repository:
        return {}
    # Listing is read-only; these only skip Borg's interactive first-access prompts.
    return {
        "BORG_REPO": backup.repository,
        "BORG_RELOCATED_REPO_ACCESS_IS_OK": "yes",
        "BORG_UNKNOWN_UNENCRYPTED_REPO_ACCESS_IS_OK": "yes",
    }


def as_utc(text: str) -> datetime:
    time = datetime.fromisoformat(text)
    return time if time.tzinfo else time.replace(tzinfo=UTC)


@adapter
class Borg(BackupAdapter):
    product = "borg"
    label = "BorgBackup"
    access = (
        "Read access to the Borg repository: either the backup container to run borg in, "
        "or the repository location and its passphrase"
    )

    def recognise(self, backup: BackupTarget, secret) -> str | None:
        try:
            out = run(backup, ["borg", "--version"], {}, secret, timeout=30)
        except CollectorError:
            return None
        return out.strip() if out.startswith("borg ") else None

    def fetch(self, backup: BackupTarget, secret) -> dict[str, Any]:
        listing = json.loads(run(backup, ["borg", "list", "--json"], _env(backup), secret))
        where = f"docker exec {backup.container}" if backup.container else backup.repository
        return {
            "source": f"borg list ({where})",
            "encryption": (listing.get("encryption") or {}).get("mode"),
            "archives": [
                {k: a.get(k) for k in ("name", "id", "start", "time")}
                for a in listing.get("archives", [])
            ],
        }

    def normalize(self, raw: dict[str, Any]) -> BackupEvidence:
        """One set per repository: Borg archive names follow no fixed grouping."""
        mode = raw.get("encryption")
        return BackupEvidence(
            repository=raw["source"],
            sets=[
                BackupSet(
                    name="repository",
                    snapshots=[
                        Snapshot(time=as_utc(a.get("start") or a["time"]), name=a["name"])
                        for a in raw["archives"]
                    ],
                    encrypted=None if mode is None else mode not in NOT_ENCRYPTED,
                )
            ],
        )
