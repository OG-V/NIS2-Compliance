"""Thin wrapper around the docker CLI."""

import subprocess

from nis2scan.registry import CollectorError


def docker(*args: str, timeout: int = 60) -> str:
    try:
        proc = subprocess.run(
            ["docker", *args], capture_output=True, text=True, timeout=timeout, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CollectorError(f"docker {args[0]}: {exc}") from exc
    if proc.returncode != 0:
        raise CollectorError(f"docker {' '.join(args[:3])}: {proc.stderr.strip()}")
    return proc.stdout
