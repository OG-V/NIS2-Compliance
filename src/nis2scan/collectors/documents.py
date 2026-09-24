"""Organisational documents: incident response plan and asset inventory."""

import hashlib

import yaml

from nis2scan.registry import Context, collector


def _read(ctx: Context, name: str) -> tuple[str, str]:
    path = ctx.target.documents.dir / name
    data = path.read_bytes()
    return data.decode(), hashlib.sha256(data).hexdigest()


@collector("ir_plan", requires="documents")
def ir_plan(ctx: Context) -> dict:
    text, digest = _read(ctx, ctx.target.documents.ir_plan)
    return {"document": ctx.target.documents.ir_plan, "sha256": digest, "text": text}


@collector("asset_inventory", requires="documents")
def asset_inventory(ctx: Context) -> dict:
    text, digest = _read(ctx, ctx.target.documents.asset_inventory)
    declared = [a["service"] for a in yaml.safe_load(text)["assets"]]
    running = [s["service"] for s in ctx.collect("docker_services")["services"]]
    return {
        "document": ctx.target.documents.asset_inventory,
        "sha256": digest,
        "declared": sorted(declared),
        "running": sorted(running),
    }
