"""Loki log store: effective retention configuration."""

import urllib.request

import yaml

from nis2scan.registry import Context, collector


@collector("loki_config", requires="logs")
def loki_config(ctx: Context) -> dict:
    with urllib.request.urlopen(f"{ctx.target.logs.url}/config", timeout=10) as resp:
        config = yaml.safe_load(resp.read())
    # /config has several keys named retention_period; only limits_config's is the
    # global log retention.
    return {
        "source": f"{ctx.target.logs.url}/config",
        "limits_config": {"retention_period": config["limits_config"]["retention_period"]},
        "compactor": {"retention_enabled": config["compactor"]["retention_enabled"]},
    }
