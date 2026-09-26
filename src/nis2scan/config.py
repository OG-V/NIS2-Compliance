"""Scan inputs: the target description and the organisational profile."""

from __future__ import annotations

import os
import re
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, PrivateAttr, field_validator, model_validator


def slug(name: str) -> str:
    """An asset name as a safe file name, for evidence files."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "asset"


class Asset(BaseModel):
    """One thing to scan in a target section, e.g. one web endpoint or one SSH host.

    `name` labels the asset in findings and reports. If it is left out, a name is
    derived from the asset's address.
    """

    name: str = ""

    def _default_name(self) -> str:
        raise NotImplementedError

    @model_validator(mode="after")
    def _set_name(self):
        self.name = self.name or self._default_name()
        return self


class WebTarget(Asset):
    host: str
    http_port: int
    https_port: int

    def _default_name(self) -> str:
        return f"{self.host}:{self.https_port}"


class SshTarget(Asset):
    host: str
    port: int
    # The effective config is read with `docker exec <container> sshd -T`. Without a
    # container only the network-visible checks run; the config checks are not applicable.
    container: str | None = None

    def _default_name(self) -> str:
        return f"{self.host}:{self.port}"


class IdpTarget(Asset):
    """An identity provider. `product` is detected from `url` unless it is set.

    The remaining fields are product-specific; each adapter lists the ones it needs.
    Secrets are never written here, only the names of environment variables holding them.
    """

    url: str
    product: str = "auto"  # or keycloak, okta, entra-id
    realm: str | None = None  # Keycloak
    admin_user: str | None = None  # Keycloak
    admin_password_env: str | None = None  # Keycloak
    api_token_env: str | None = None  # Okta
    client_id: str | None = None  # Entra ID app registration
    client_secret_env: str | None = None  # Entra ID

    def _default_name(self) -> str:
        return self.realm or urlparse(self.url).hostname or self.url


class LogsTarget(Asset):
    """A log store. `product` is detected unless it is set.

    Self-hosted stores are reached at `url`; Microsoft Sentinel through its Azure
    subscription and Log Analytics workspace.
    """

    url: str | None = None
    product: str = "auto"  # or loki, elasticsearch, splunk, sentinel
    username: str | None = None  # Elasticsearch, Splunk
    password_env: str | None = None  # Elasticsearch, Splunk
    api_key_env: str | None = None  # Elasticsearch, instead of username and password
    token_env: str | None = None  # Splunk authentication token, instead of a password
    indices: str = "*"  # Elasticsearch and Splunk: which indices hold logs
    ca_file: Path | None = None  # certificate to trust for a self-signed server (Splunk)
    tls_fingerprint: str | None = None  # or pin the server's certificate (SHA-256)
    # Microsoft Sentinel: the Log Analytics workspace, read with an Entra app registration.
    subscription: str | None = None
    workspace: str | None = None  # workspace name; all Sentinel workspaces if left out
    tenant: str | None = None
    client_id: str | None = None
    client_secret_env: str | None = None

    @model_validator(mode="after")
    def _where(self):
        if not (self.url or self.subscription):
            raise ValueError("a log store needs url, or subscription (Microsoft Sentinel)")
        return self

    def _default_name(self) -> str:
        if self.url:
            return self.url
        return f"sentinel-{self.workspace or (self.subscription or 'unknown')[:8]}"


class BackupTarget(Asset):
    """A backup repository. `product` is detected unless it is set.

    Either `container` (the backup tool runs inside it, already configured with its
    repository and password) or `repository` plus `password_env` (the tool runs on the
    scanning host) must be given.
    """

    product: str = "auto"  # or restic, borg, veeam
    container: str | None = None
    repository: str | None = None  # e.g. s3:..., sftp:..., /srv/backups/repo
    password_env: str | None = None  # the repository password, or the backup server's
    url: str | None = None  # a backup server's API, e.g. https://vbr.example:9419 (Veeam)
    username: str | None = None  # for a backup server's API
    ca_file: Path | None = None  # certificate to trust for a self-signed server
    tls_fingerprint: str | None = None  # or pin the server's certificate (SHA-256)
    api_version: str = "1.1-rev0"  # Veeam REST API version header (VBR 12.0 and later)
    # AWS Backup: a region, and either a named AWS CLI profile or access keys in secrets.
    region: str | None = None
    aws_profile: str | None = None
    access_key_id_env: str | None = None
    secret_access_key_env: str | None = None
    # Azure Backup: a subscription, read with an Entra app registration.
    subscription: str | None = None
    tenant: str | None = None
    client_id: str | None = None
    client_secret_env: str | None = None

    @model_validator(mode="after")
    def _one_way_in(self):
        if not (self.container or self.repository or self.url or self.region or self.subscription):
            raise ValueError(
                "a backup asset needs container, repository, url, region (AWS) "
                "or subscription (Azure)"
            )
        return self

    def _default_name(self) -> str:
        if self.url:
            return urlparse(self.url).hostname or self.url
        if self.region:
            return f"aws-backup-{self.region}"
        if self.subscription:
            return f"azure-backup-{self.subscription[:8]}"
        return self.container or self.repository


class DockerTarget(Asset):
    compose_project: str

    def _default_name(self) -> str:
        return self.compose_project


class DocumentsTarget(Asset):
    dir: Path
    ir_plan: str
    asset_inventory: str
    risk_exceptions: str | None = None  # accepted vulnerability risks, optional

    def _default_name(self) -> str:
        return "documents"


class Engagement(BaseModel):
    """The agreed scope of a scan: who authorised it, for how long, and what is allowed.

    Active tests interact with a system beyond reading it (e.g. trying a default admin
    password once). They can trigger the client's alerts or, repeated, lock accounts, so
    they run only when the engagement allows them.
    """

    client: str
    authorised_by: str  # name and role of the person who authorised the scan
    authorised_on: date
    valid_until: date
    active_tests: bool = False
    notes: str = ""

    def covers(self, day: date) -> bool:
        return self.authorised_on <= day <= self.valid_until


# Sections that can list several assets. `documents` is organisation-wide, so it is single.
ASSET_SECTIONS = ("web", "ssh", "idp", "logs", "backup", "docker")


class Target(BaseModel):
    """What to scan. Sections left out make the checks that need them not applicable.

    Each section in ASSET_SECTIONS takes a list of assets. A single mapping is also
    accepted, for targets with one asset of that kind.
    """

    name: str
    # Files of NAME=value lines holding secrets; one path or a list. Missing files are skipped.
    env_file: list[Path] = []
    web: list[WebTarget] = []
    ssh: list[SshTarget] = []
    idp: list[IdpTarget] = []
    logs: list[LogsTarget] = []
    backup: list[BackupTarget] = []
    docker: list[DockerTarget] = []
    documents: DocumentsTarget | None = None
    engagement: Engagement | None = None

    _env: dict[str, str] = PrivateAttr(default_factory=dict)

    @property
    def active_tests_allowed(self) -> bool:
        return self.engagement is not None and self.engagement.active_tests

    @field_validator("env_file", mode="before")
    @classmethod
    def _one_or_more_files(cls, value):
        if value is None:
            return []
        return [value] if isinstance(value, (str, Path)) else value

    @field_validator(*ASSET_SECTIONS, mode="before")
    @classmethod
    def _one_or_many(cls, value):
        if value is None:
            return []
        return [value] if isinstance(value, dict) else value

    @model_validator(mode="after")
    def _unique_names(self):
        for section in ASSET_SECTIONS:
            names = [a.name for a in getattr(self, section)]
            if duplicates := sorted({n for n in names if names.count(n) > 1}):
                raise ValueError(f"duplicate {section} asset names: {', '.join(duplicates)}")
        return self

    def assets(self, section: str) -> list[Asset]:
        """The assets a collector with `requires=section` runs against."""
        if section == "documents":
            return [self.documents] if self.documents else []
        return list(getattr(self, section))

    def secret(self, name: str) -> str:
        """Look up a secret in the process environment, then in the env files."""
        value = os.environ.get(name) or self._env.get(name)
        if not value:
            files = ", ".join(str(f) for f in self.env_file) or "no env_file"
            raise KeyError(f"secret {name} is not set in the environment or in {files}")
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
    target.env_file = [base / f for f in target.env_file]
    for env_file in target.env_file:
        if env_file.exists():
            target._env |= parse_env_file(env_file.read_text())
    if target.documents:
        target.documents.dir = base / target.documents.dir
    for asset in (*target.backup, *target.logs):
        if asset.ca_file:
            asset.ca_file = base / asset.ca_file
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
