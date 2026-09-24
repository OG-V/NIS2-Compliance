"""Scan inputs: the target description and the organisational profile."""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel, PrivateAttr


class WebTarget(BaseModel):
    host: str
    http_port: int
    https_port: int


class SshTarget(BaseModel):
    host: str
    port: int
    container: str  # effective config is read with `docker exec <container> sshd -T`


class IdpTarget(BaseModel):
    url: str
    realm: str
    admin_user: str
    admin_password_env: str


class LogsTarget(BaseModel):
    url: str


class BackupTarget(BaseModel):
    container: str  # restic runs inside it, with the repository configured by env


class DockerTarget(BaseModel):
    compose_project: str


class DocumentsTarget(BaseModel):
    dir: Path
    ir_plan: str
    asset_inventory: str
    risk_exceptions: str | None = None  # accepted vulnerability risks, optional


class Target(BaseModel):
    """What to scan. Sections left out make the checks that need them not applicable."""

    name: str
    env_file: Path | None = None
    web: WebTarget | None = None
    ssh: SshTarget | None = None
    idp: IdpTarget | None = None
    logs: LogsTarget | None = None
    backup: BackupTarget | None = None
    docker: DockerTarget | None = None
    documents: DocumentsTarget | None = None

    _env: dict[str, str] = PrivateAttr(default_factory=dict)

    def secret(self, name: str) -> str:
        """Look up a secret in the process environment, then in env_file."""
        value = os.environ.get(name) or self._env.get(name)
        if not value:
            raise KeyError(f"secret {name} is not set in the environment or {self.env_file}")
        return value


def parse_env_file(text: str) -> dict[str, str]:
    env = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        env[key.strip()] = value
    return env


def load_target(path: Path) -> Target:
    """Load a target file; relative paths in it are resolved against its directory."""
    base = path.resolve().parent
    target = Target.model_validate(yaml.safe_load(path.read_text()))
    if target.env_file:
        target.env_file = base / target.env_file
        if target.env_file.exists():
            target._env = parse_env_file(target.env_file.read_text())
    if target.documents:
        target.documents.dir = base / target.documents.dir
    return target


class TlsProfile(BaseModel):
    min_version: str
    cert_min_days_remaining: int


class SshProfile(BaseModel):
    max_auth_tries: int


class IdentityProfile(BaseModel):
    min_password_length: int


class LoggingProfile(BaseModel):
    min_retention_days: int


class BackupProfile(BaseModel):
    max_age_hours: int


class VulnerabilityProfile(BaseModel):
    fail_on_severity: list[str]
    only_with_fix: bool


class IncidentResponseProfile(BaseModel):
    max_review_age_days: int


class Profile(BaseModel):
    """The organisation's chosen thresholds (catalog/profile.yaml). Rationale keys are ignored."""

    tls: TlsProfile
    ssh: SshProfile
    identity: IdentityProfile
    logging: LoggingProfile
    backup: BackupProfile
    vulnerabilities: VulnerabilityProfile
    incident_response: IncidentResponseProfile


def load_profile(path: Path) -> Profile:
    return Profile.model_validate(yaml.safe_load(path.read_text()))
