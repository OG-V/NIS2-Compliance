"""Onboarding: what access the client has to grant, and whether it is in place yet.

For every system in the target this lists, in words a client's IT staff can act on,
the access a scan needs: network reachability, an admin API credential, Docker
access, documents. With probing on, it checks each item: it connects to ports,
detects identity products, looks for containers, checks that secrets are set
(never reading them out) and that documents exist. Nothing here changes a system.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from datetime import date
from urllib.parse import urlparse

from nis2scan.adapters._http import server_fingerprint
from nis2scan.adapters.backup import ADAPTERS as BACKUP_ADAPTERS
from nis2scan.adapters.identity import ADAPTERS
from nis2scan.adapters.identity.detect import LABELS, detect
from nis2scan.adapters.logging import ADAPTERS as LOG_ADAPTERS
from nis2scan.collectors._docker import docker
from nis2scan.collectors.backup import detect as backup_detect
from nis2scan.collectors.logging import detect as log_detect
from nis2scan.config import Target
from nis2scan.registry import CollectorError

OK, MISSING, OPTIONAL, UNVERIFIED = "ok", "missing", "optional", "not checked"
KINDS = {
    "web": "Web endpoint",
    "ssh": "SSH host",
    "idp": "Identity provider",
    "logs": "Log store",
    "backup": "Backup repository",
    "docker": "Docker project",
    "documents": "Documents",
}


@dataclass
class Access:
    what: str  # what the client has to provide, in plain words
    status: str = UNVERIFIED  # ok | missing | optional | not checked
    note: str = ""


@dataclass
class System:
    section: str
    name: str
    product: str | None = None
    identified_by: str = ""
    access: list[Access] = field(default_factory=list)

    @property
    def kind(self) -> str:
        return KINDS[self.section]

    @property
    def ready(self) -> bool:
        return all(a.status in (OK, OPTIONAL) for a in self.access)


def reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def container_exists(name: str) -> bool:
    try:
        docker("inspect", "--type", "container", name, timeout=15)
        return True
    except CollectorError:
        return False


def compose_project_running(project: str) -> bool:
    try:
        return bool(
            docker(
                "ps", "-q", "--filter", f"label=com.docker.compose.project={project}", timeout=15
            ).split()
        )
    except CollectorError:
        return False


def _status(ok: bool, probe: bool) -> str:
    return (OK if ok else MISSING) if probe else UNVERIFIED


def _url_access(url: str, what: str, probe: bool) -> Access:
    parsed = urlparse(url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    status = _status(probe and reachable(parsed.hostname or "", port), probe)
    return Access(
        what, status, "" if status != MISSING else f"cannot connect to {parsed.hostname}:{port}"
    )


def _identity(system: System, idp, target: Target, probe: bool) -> None:
    product = idp.product if idp.product != "auto" else None
    if product:
        system.identified_by = "set in the target file"
    elif probe:
        try:
            d = detect(idp)
            product, system.identified_by = d.product, f"identified from its {d.method}: {d.detail}"
        except CollectorError as exc:
            # detect() explains every URL it tried; the first sentence is enough here.
            system.identified_by = (
                "not identified: " + str(exc).split("; set", 1)[0].split(". ", 1)[0]
            )
    system.access.append(_url_access(idp.url, f"Network access to {idp.url}", probe))
    if product not in ADAPTERS:
        system.product = LABELS.get(product or "", product)
        system.access.append(
            Access("A supported identity product", MISSING, "set `product:` or check the URL")
            if not product
            else Access(f"Support for {system.product}", MISSING, "no adapter for this product yet")
        )
        return
    adapter = ADAPTERS[product]
    system.product = adapter.label
    credential = Access(adapter.access)
    system.access.append(credential)
    complete = True
    for name in adapter.needs:
        value = getattr(idp, name)
        if not value:
            system.access.append(Access(f"`{name}` in the target file", MISSING))
            complete = False
        elif name.endswith("_env"):
            try:
                target.secret(value)
            except KeyError:
                credential.status, credential.note = MISSING, f"secret {value} is not set"
                complete = False
    if probe and complete and credential.status == UNVERIFIED:
        try:
            adapter.check_access(idp, target.secret)
            credential.status, credential.note = OK, "tested with one read-only request"
        except CollectorError as exc:
            credential.status, credential.note = MISSING, f"refused: {exc}"


def _refusal(exc: Exception, url: str | None) -> str:
    """Why access failed; for an untrusted certificate, the fingerprint to confirm."""
    if url and "CERTIFICATE_VERIFY_FAILED" in str(exc):
        parsed = urlparse(url)
        try:
            presented = server_fingerprint(parsed.hostname, parsed.port or 443)
        except (OSError, ValueError):
            return f"refused: {exc}"
        return (
            f"its certificate is not trusted. Its SHA-256 fingerprint is {presented}: "
            "confirm it with the client, then set it as tls_fingerprint (or give ca_file)"
        )
    return f"refused: {exc}"


def _log_store(system: System, logs, target: Target, probe: bool) -> None:
    if logs.url:
        system.access.append(_url_access(logs.url, f"Network access to {logs.url}", probe))
    if logs.product != "auto":
        product, system.identified_by = logs.product, "set in the target file"
    elif probe:
        try:
            found = log_detect(logs, target.secret)
            product, system.identified_by = (
                found["product"],
                f"identified from its {found['method']}",
            )
        except CollectorError as exc:
            product, system.identified_by = None, f"not identified: {str(exc).split(';')[0]}"
    else:
        product = None
    if product not in LOG_ADAPTERS:
        if probe or product:
            system.access.append(
                Access("A supported log store", MISSING, "set `product:` or check the URL")
            )
        return
    adapter = LOG_ADAPTERS[product]
    system.product = adapter.label
    credential = Access(adapter.access)
    system.access.append(credential)
    if probe:
        try:
            adapter.check_access(logs, target.secret)
            credential.status, credential.note = OK, "tested with one read-only request"
        except KeyError as exc:
            credential.status, credential.note = MISSING, str(exc).strip("'")
        except CollectorError as exc:
            credential.status, credential.note = MISSING, _refusal(exc, logs.url)


def _backup(system: System, backup, target: Target, probe: bool) -> None:
    if backup.url:
        system.access.append(_url_access(backup.url, f"Network access to {backup.url}", probe))
    if backup.container:
        system.access.append(
            Access(
                f"Docker access to container {backup.container}, where the backup tool runs "
                "with its repository configured",
                _status(probe and container_exists(backup.container), probe),
            )
        )
    if backup.product != "auto":
        product, system.identified_by = backup.product, "set in the target file"
    elif probe:
        try:
            found = backup_detect(backup, target.secret)
            product, system.identified_by = found["product"], f"identified: {found['method']}"
        except CollectorError as exc:
            product, system.identified_by = None, f"not identified: {str(exc).split(';')[0]}"
    else:
        product = None
    if product not in BACKUP_ADAPTERS:
        if probe or product:
            system.access.append(
                Access("A supported backup tool", MISSING, "set `product:` or check the container")
            )
        return
    adapter = BACKUP_ADAPTERS[product]
    system.product = adapter.label
    credential = Access(adapter.access)
    system.access.append(credential)
    if probe:
        try:
            adapter.check_access(backup, target.secret)
            credential.status, credential.note = OK, "tested with a read-only request"
        except KeyError as exc:
            credential.status, credential.note = MISSING, str(exc).strip("'")
        except CollectorError as exc:
            credential.status, credential.note = MISSING, _refusal(exc, backup.url)


def plan(target: Target, probe: bool = True) -> list[System]:
    """Every system in the target, with the access it needs and whether that is in place."""
    systems = []
    for web in target.web:
        s = System("web", web.name)
        for port, what in ((web.https_port, "HTTPS"), (web.http_port, "HTTP")):
            ok = probe and reachable(web.host, port)
            s.access.append(
                Access(f"Network access to {web.host} port {port} ({what})", _status(ok, probe))
            )
        systems.append(s)
    for ssh in target.ssh:
        s = System("ssh", ssh.name)
        s.access.append(
            Access(
                f"Network access to {ssh.host} port {ssh.port} (SSH)",
                _status(probe and reachable(ssh.host, ssh.port), probe),
            )
        )
        if ssh.container:
            s.access.append(
                Access(
                    f"Docker access to container {ssh.container}, to read the effective sshd configuration",
                    _status(probe and container_exists(ssh.container), probe),
                )
            )
        else:
            s.access.append(
                Access(
                    "Read access to the sshd configuration (set `container:`)",
                    OPTIONAL,
                    "without it, the root-login and login-attempt checks are skipped",
                )
            )
        systems.append(s)
    for idp in target.idp:
        s = System("idp", idp.name)
        _identity(s, idp, target, probe)
        systems.append(s)
    for logs in target.logs:
        s = System("logs", logs.name)
        _log_store(s, logs, target, probe)
        systems.append(s)
    for backup in target.backup:
        s = System("backup", backup.name)
        _backup(s, backup, target, probe)
        systems.append(s)
    for project in target.docker:
        s = System("docker", project.name, product="Docker Compose")
        s.access.append(
            Access(
                f"Access to the Docker engine running compose project {project.compose_project}, "
                "and permission to run the pinned Trivy image against its images",
                _status(probe and compose_project_running(project.compose_project), probe),
            )
        )
        systems.append(s)
    if target.documents:
        docs = target.documents
        s = System("documents", docs.name)
        for filename, what in (
            (docs.ir_plan, "Incident response plan"),
            (docs.asset_inventory, "Asset inventory"),
        ):
            s.access.append(
                Access(f"{what}: {filename}", OK if (docs.dir / filename).exists() else MISSING)
            )
        if docs.risk_exceptions:
            exists = (docs.dir / docs.risk_exceptions).exists()
            s.access.append(
                Access(
                    f"Risk exception register: {docs.risk_exceptions}", OK if exists else OPTIONAL
                )
            )
        systems.append(s)
    return systems


def authorisation(target: Target, today: date) -> Access:
    """Whether written authorisation for the scan is recorded and valid today."""
    e = target.engagement
    if e is None:
        return Access("Written authorisation for the scan (an `engagement` section)", MISSING)
    what = f"Authorised by {e.authorised_by} for {e.client}, {e.authorised_on} to {e.valid_until}"
    if not e.covers(today):
        return Access(what, MISSING, f"not valid on {today}")
    return Access(
        what, OK, "active tests allowed" if e.active_tests else "active tests not allowed"
    )


def checklist_markdown(target: Target, systems: list[System], auth: Access) -> str:
    """The checklist as a document to send to the client."""
    box = {OK: "[x]", OPTIONAL: "[ ]", MISSING: "[ ]", UNVERIFIED: "[ ]"}
    lines = [
        f"# Access checklist: {target.name}",
        "",
        (
            "Everything the NIS2 evidence scan needs. The scan only reads configuration; "
            "it changes nothing. Secrets are never included in results or reports."
        ),
        "",
        "## Authorisation",
        "",
        f"- {box[auth.status]} {auth.what}" + (f" · {auth.note}" if auth.note else ""),
    ]
    for s in systems:
        product = f" ({s.product})" if s.product else ""
        lines += ["", f"## {s.kind}: {s.name}{product}", ""]
        for a in s.access:
            note = f" · {a.note}" if a.note else ""
            optional = " (optional)" if a.status == OPTIONAL else ""
            lines.append(f"- {box[a.status]} {a.what}{optional}{note}")
    return "\n".join(lines) + "\n"
