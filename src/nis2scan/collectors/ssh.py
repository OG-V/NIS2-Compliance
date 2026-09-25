"""SSH: authentication methods offered live, and sshd's effective configuration."""

import paramiko

from nis2scan.collectors._docker import docker
from nis2scan.config import SshTarget
from nis2scan.registry import Context, NotApplicable, collector


@collector("ssh_auth_methods", requires="ssh")
def ssh_auth_methods(ctx: Context, ssh: SshTarget) -> dict:
    """Ask the server which auth methods it offers, without attempting to log in."""
    transport = paramiko.Transport((ssh.host, ssh.port))
    try:
        transport.start_client(timeout=10)
        try:
            transport.auth_none("root")
            methods = ["none"]  # the server let us in without authenticating at all
        except paramiko.BadAuthenticationType as exc:
            methods = sorted(exc.allowed_types)
        return {
            "endpoint": f"{ssh.host}:{ssh.port}",
            "server_version": transport.remote_version,
            "auth_methods_offered": methods,
        }
    finally:
        transport.close()


def parse_sshd_t(output: str) -> dict[str, str | list[str]]:
    """Parse `sshd -T` output. Keys that repeat (e.g. hostkey) become lists."""
    config: dict[str, str | list[str]] = {}
    for line in output.splitlines():
        key, _, value = line.strip().partition(" ")
        if not key:
            continue
        if key in config:
            existing = config[key]
            config[key] = [*existing, value] if isinstance(existing, list) else [existing, value]
        else:
            config[key] = value
    return config


@collector("sshd_effective_config", requires="ssh")
def sshd_effective_config(ctx: Context, ssh: SshTarget) -> dict:
    if not ssh.container:
        raise NotApplicable("no container given, so the effective sshd config cannot be read")
    output = docker("exec", ssh.container, "sshd", "-T")
    return {
        "source": f"docker exec {ssh.container} sshd -T",
        "config": parse_sshd_t(output),
    }
