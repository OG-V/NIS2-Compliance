"""Veeam Backup & Replication: backups, their newest restore points and job encryption.

Uses the VBR REST API (port 9419 by default, VBR 12 and later) with an account that
has the Veeam Backup Viewer role. Every request carries the `x-api-version` header
the API requires; the target's `api_version` sets it (1.1-rev0 works from 12.0).

- POST /api/oauth2/token             (grant_type=password) for a bearer token
- GET  /api/v1/serverInfo            product and build, used to recognise the server
- GET  /api/v1/backups               one backup per job: each is a backup set
- GET  /api/v1/restorePoints         the newest restore point per backup
- GET  /api/v1/jobs                  each job's storage.advancedSettings.storageData.encryption

A backup whose job the API does not show (for example some agent backups) has unknown
encryption, which the encryption check reports as not determinable, never as a pass.
Built from Veeam's REST API reference; not yet run against a live server.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import urlencode

from nis2scan.adapters._http import HttpError, get_json, request, trust
from nis2scan.adapters.backup import BackupAdapter, BackupEvidence, BackupSet, Snapshot, adapter
from nis2scan.config import BackupTarget
from nis2scan.registry import CollectorError

PAGE = 200


class _Session:
    def __init__(self, backup: BackupTarget, secret):
        if not (backup.url and backup.username and backup.password_env):
            raise CollectorError("Veeam needs url, username and password_env set in the target")
        self.base = backup.url.rstrip("/")
        self.context = trust(str(backup.ca_file) if backup.ca_file else None)
        self.version = {"x-api-version": backup.api_version}
        body, _ = request(
            f"{self.base}/api/oauth2/token",
            headers=self.version,
            data={
                "grant_type": "password",
                "username": backup.username,
                "password": secret(backup.password_env),
            },
            context=self.context,
        )
        self.headers = {**self.version, "Authorization": f"Bearer {body['access_token']}"}

    def get(self, path: str, **params) -> Any:
        query = f"?{urlencode(params)}" if params else ""
        return get_json(f"{self.base}{path}{query}", self.headers, self.context)

    def all(self, path: str, **params) -> list:
        """Every item of a paged list ({"data": [...], "pagination": {"total": n}})."""
        items: list = []
        while True:
            page = self.get(path, skip=len(items), limit=PAGE, **params)
            items.extend(page.get("data", []))
            total = (page.get("pagination") or {}).get("total", len(items))
            if not page.get("data") or len(items) >= total:
                return items


def job_encryption(job: dict) -> bool | None:
    storage = job.get("storage") or {}
    data = ((storage.get("advancedSettings") or {}).get("storageData")) or {}
    encryption = data.get("encryption")
    return None if encryption is None else bool(encryption.get("isEnabled"))


@adapter
class Veeam(BackupAdapter):
    product = "veeam"
    label = "Veeam Backup & Replication"
    access = (
        "A Veeam Backup & Replication account with the Veeam Backup Viewer role, for the "
        "REST API (port 9419), and the server's certificate if it is self-signed"
    )

    def recognise(self, backup: BackupTarget, secret) -> str | None:
        if not backup.url:
            return None
        try:
            info = _Session(backup, secret).get("/api/v1/serverInfo")
        except (CollectorError, KeyError):
            return None
        build = info.get("buildVersion")
        return f"Veeam Backup & Replication {build}" if build else None

    def check_access(self, backup: BackupTarget, secret) -> None:
        _Session(backup, secret).get("/api/v1/serverInfo")

    def fetch(self, backup: BackupTarget, secret) -> dict[str, Any]:
        session = _Session(backup, secret)
        jobs = {j["id"]: j for j in session.all("/api/v1/jobs")}
        backups = []
        for b in session.all("/api/v1/backups"):
            try:
                newest = session.get(
                    "/api/v1/restorePoints",
                    backupIdFilter=b["id"],
                    orderColumn="CreationTime",
                    orderAsc="false",
                    limit=1,
                ).get("data", [])
            except HttpError as exc:
                raise CollectorError(f"restore points of backup {b.get('name')}: {exc}") from None
            job = jobs.get(b.get("jobId"))
            backups.append(
                {
                    "name": b.get("name"),
                    "jobId": b.get("jobId"),
                    "platformName": b.get("platformName"),
                    "newestRestorePoint": (
                        {k: newest[0].get(k) for k in ("id", "name", "creationTime")}
                        if newest
                        else None
                    ),
                    "jobEncryption": job_encryption(job) if job else None,
                    "jobDisabled": job.get("isDisabled") if job else None,
                }
            )
        return {"server": session.base, "backups": backups}

    def normalize(self, raw: dict[str, Any]) -> BackupEvidence:
        sets = []
        for b in raw["backups"]:
            point = b.get("newestRestorePoint")
            snapshots = (
                [
                    Snapshot(
                        time=datetime.fromisoformat(point["creationTime"]),
                        name=point.get("name") or "",
                    )
                ]
                if point
                else []
            )
            sets.append(
                BackupSet(name=b["name"], snapshots=snapshots, encrypted=b.get("jobEncryption"))
            )
        return BackupEvidence(
            repository=f"Veeam Backup & Replication at {raw['server']}", sets=sets
        )
