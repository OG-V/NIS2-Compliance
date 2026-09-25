"""restic: snapshots from `restic snapshots --json`.

restic always encrypts its repositories, so `encrypted` is always true. Listing
snapshots only reads the repository.
"""

from __future__ import annotations

import json
import re
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


def parse_time(text: str) -> datetime:
    """restic's RFC 3339 times, which can carry nanoseconds Python does not parse."""
    head, dot, rest = text.partition(".")
    if dot:
        digits = re.match(r"\d*", rest).group()  # the fraction only, not the offset after it
        text = f"{head}.{digits[:6]}{rest[len(digits) :]}"
    return datetime.fromisoformat(text)


def _env(backup: BackupTarget) -> dict[str, str]:
    return {"RESTIC_REPOSITORY": backup.repository} if backup.repository else {}


@adapter
class Restic(BackupAdapter):
    product = "restic"
    label = "restic"
    access = (
        "Read access to the restic repository: either the backup container to run restic "
        "in, or the repository location and its password"
    )

    def recognise(self, backup: BackupTarget, secret) -> str | None:
        try:
            out = run(backup, ["restic", "version"], {}, secret, timeout=30)
        except CollectorError:
            return None
        return out.strip().split(" compiled")[0] if out.startswith("restic ") else None

    def fetch(self, backup: BackupTarget, secret) -> dict[str, Any]:
        snapshots = json.loads(run(backup, ["restic", "snapshots", "--json"], _env(backup), secret))
        where = f"docker exec {backup.container}" if backup.container else backup.repository
        return {
            "source": f"restic snapshots ({where})",
            "snapshots": [
                {k: s.get(k) for k in ("short_id", "time", "hostname", "paths")} for s in snapshots
            ],
        }

    def normalize(self, raw: dict[str, Any]) -> BackupEvidence:
        """One set per host and paths, as restic itself groups snapshots."""
        groups: dict[str, list[Snapshot]] = {}
        for s in raw["snapshots"]:
            paths = s.get("paths") or []
            key = f"{s.get('hostname') or '?'}:{','.join(sorted(paths))}"
            groups.setdefault(key, []).append(
                Snapshot(
                    time=parse_time(s["time"]),
                    host=s.get("hostname"),
                    paths=paths,
                    name=s.get("short_id") or "",
                )
            )
        return BackupEvidence(
            repository=raw["source"],
            # restic has no unencrypted repositories
            sets=[
                BackupSet(name=k, snapshots=v, encrypted=True) for k, v in sorted(groups.items())
            ],
        )
