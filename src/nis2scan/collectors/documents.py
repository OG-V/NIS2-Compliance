"""Organisational documents: incident response plan and asset inventory."""

import hashlib

import yaml

from nis2scan.config import DocumentsTarget
from nis2scan.registry import Context, collector


def _read(docs: DocumentsTarget, name: str) -> tuple[str, str]:
    path = docs.dir / name
    data = path.read_bytes()
    return data.decode(), hashlib.sha256(data).hexdigest()


@collector("ir_plan", requires="documents")
def ir_plan(ctx: Context, docs: DocumentsTarget) -> dict:
    text, digest = _read(docs, docs.ir_plan)
    return {"document": docs.ir_plan, "sha256": digest, "text": text}


@collector("asset_inventory", requires="documents")
def asset_inventory(ctx: Context, docs: DocumentsTarget) -> dict:
    text, digest = _read(docs, docs.asset_inventory)
    declared = [a["service"] for a in yaml.safe_load(text)["assets"]]
    # The inventory covers the whole organisation: compare it with every Docker project.
    running = {
        s["service"]
        for project in ctx.target.docker
        for s in ctx.collect("docker_services", project)["services"]
    }
    return {
        "document": docs.asset_inventory,
        "sha256": digest,
        "declared": sorted(declared),
        "running": sorted(running),
    }
