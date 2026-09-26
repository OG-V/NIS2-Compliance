"""Backup tools: the product-neutral snapshot model, adapters and how the tool is run.

The backup checks read only BackupEvidence. A repository or backup server usually
holds several backup sets (one per backed-up host, or per backup job); each is judged
on its own, because one stopped job must not hide behind another's fresh backups. Backup tools are command-line programs,
so an adapter runs its tool's read-only listing command, either inside the client's
backup container (already configured with the repository and password) or on the
scanning host with the repository and a password from the target's secrets.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from datetime import datetime
from typing import Any, ClassVar

from pydantic import BaseModel

from nis2scan.collectors._docker import docker
from nis2scan.config import BackupTarget
from nis2scan.registry import CollectorError


class Snapshot(BaseModel):
    time: datetime  # timezone-aware
    host: str | None = None
    paths: list[str] = []
    name: str = ""  # snapshot ID or archive name


class BackupSet(BaseModel):
    name: str  # e.g. "nordmsp:/data" (host and paths) or a backup job's name
    snapshots: list[Snapshot]
    encrypted: bool | None = None  # None when the tool does not say

    @property
    def newest(self) -> Snapshot | None:
        return max(self.snapshots, key=lambda s: s.time) if self.snapshots else None


class BackupEvidence(BaseModel):
    repository: str  # the repository or backup server read
    sets: list[BackupSet]

    @property
    def stalest(self) -> BackupSet | None:
        """The set whose newest snapshot is oldest; a set without snapshots first."""
        if not self.sets:
            return None
        return min(
            self.sets, key=lambda s: (s.newest is not None, s.newest.time if s.newest else 0)
        )


def run(
    backup: BackupTarget,
    argv: list[str],
    local_env: dict[str, str],
    secret,
    timeout: int = 120,
) -> str:
    """Run a backup tool's command in the backup container, or on this host.

    `local_env` maps the tool's variables to their values for local runs, where the
    password is taken from the target's secrets (never passed on the command line).
    """
    if backup.container:
        return docker("exec", backup.container, *argv, timeout=timeout)
    if not shutil.which(argv[0]):
        raise CollectorError(f"{argv[0]} is not installed on the scanning host")
    env = {**os.environ, **local_env}
    if backup.password_env and argv[0] in PASSWORD_VARIABLES:
        env[PASSWORD_VARIABLES[argv[0]]] = secret(backup.password_env)
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, env=env, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CollectorError(f"{argv[0]}: {exc}") from exc
    if proc.returncode != 0:
        raise CollectorError(f"{' '.join(argv[:2])}: {proc.stderr.strip()[:300]}")
    return proc.stdout


PASSWORD_VARIABLES = {"restic": "RESTIC_PASSWORD", "borg": "BORG_PASSPHRASE"}


class BackupAdapter:
    product: ClassVar[str]
    label: ClassVar[str]
    access: ClassVar[str] = ""

    def recognise(self, backup: BackupTarget, secret) -> str | None:
        """The tool's version line if this tool is present where it would run, else None."""
        raise NotImplementedError

    def fetch(self, backup: BackupTarget, secret) -> dict[str, Any]:
        raise NotImplementedError

    def check_access(self, backup: BackupTarget, secret) -> None:
        """A cheap read with the given access; by default, a full listing."""
        self.fetch(backup, secret)

    def normalize(self, raw: dict[str, Any]) -> BackupEvidence:
        raise NotImplementedError


ADAPTERS: dict[str, BackupAdapter] = {}


def adapter(cls: type[BackupAdapter]) -> type[BackupAdapter]:
    ADAPTERS[cls.product] = cls()
    return cls


# Imported for their @adapter registrations.
from nis2scan.adapters.backup import aws, azure, borg, restic, veeam  # noqa: F401
