"""Backup repositories: which tool manages them, and their snapshots.

The tool is detected (or taken from the target), then its adapter lists the
snapshots and normalises them. Evidence keeps both.
"""

from nis2scan.adapters.backup import ADAPTERS
from nis2scan.config import BackupTarget
from nis2scan.registry import CollectorError, Context, collector


def detect(backup: BackupTarget, secret) -> dict:
    if backup.product != "auto":
        if backup.product not in ADAPTERS:
            raise CollectorError(
                f"unknown backup tool {backup.product!r}; supported: {', '.join(sorted(ADAPTERS))}"
            )
        return {"product": backup.product, "method": "configured", "detail": ""}
    for adapter in ADAPTERS.values():
        if version := adapter.recognise(backup, secret):
            where = f"container {backup.container}" if backup.container else "the scanning host"
            return {
                "product": adapter.product,
                "method": f"{version} found in {where}",
                "detail": "",
            }
    raise CollectorError(
        f"no supported backup tool found for {backup.name}; set `product:` in the target "
        f"(supported: {', '.join(sorted(ADAPTERS))})"
    )


@collector("backup_detect", requires="backup")
def backup_detect(ctx: Context, backup: BackupTarget) -> dict:
    found = detect(backup, ctx.target.secret)
    return {**found, "label": ADAPTERS[found["product"]].label}


@collector("backup_snapshots", requires="backup")
def backup_snapshots(ctx: Context, backup: BackupTarget) -> dict:
    adapter = ADAPTERS[ctx.collect("backup_detect", backup)["product"]]
    raw = adapter.fetch(backup, ctx.target.secret)
    return {
        "product": adapter.product,
        "backup": adapter.normalize(raw).model_dump(mode="json"),
        "raw": raw,
    }
