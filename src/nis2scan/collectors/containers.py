"""Docker-based evidence: running services and image vulnerabilities."""

import json
from pathlib import Path

import yaml

from nis2scan.collectors._docker import docker
from nis2scan.config import DockerTarget
from nis2scan.registry import CollectorError, Context, collector

# Pinned by digest: a security scanner should not silently pull a changed image.
TRIVY_IMAGE = (
    "aquasec/trivy:0.73.0@sha256:7cced7cae583819fc7806d4cbc0dbbc7cad18b99f7d3e235192e6da8c091045c"
)
TRIVY_CACHE = Path.home() / ".cache" / "nis2scan" / "trivy"


@collector("docker_services", requires="docker")
def docker_services(ctx: Context, asset: DockerTarget) -> dict:
    project = asset.compose_project
    ids = docker("ps", "-q", "--filter", f"label=com.docker.compose.project={project}").split()
    services = []
    if ids:
        for c in json.loads(docker("inspect", *ids)):
            services.append(
                {
                    "service": c["Config"]["Labels"].get("com.docker.compose.service"),
                    "container": c["Name"].lstrip("/"),
                    "image": c["Config"]["Image"],
                    "image_id": c["Image"],
                }
            )
    return {"compose_project": project, "services": sorted(services, key=lambda s: s["service"])}


def _trivy(image: str) -> dict:
    TRIVY_CACHE.mkdir(parents=True, exist_ok=True)
    report = json.loads(
        docker(
            "run", "--rm",
            "-v", "/var/run/docker.sock:/var/run/docker.sock:ro",
            "-v", f"{TRIVY_CACHE}:/root/.cache/trivy",
            TRIVY_IMAGE,
            "image", "--quiet", "--format", "json", "--scanners", "vuln",
            "--severity", "HIGH,CRITICAL", image,
            timeout=900,
        )
    )  # fmt: skip
    vulns = [
        {
            "id": v["VulnerabilityID"],
            "package": v["PkgName"],
            "installed": v.get("InstalledVersion"),
            "fixed": v.get("FixedVersion") or None,
            "severity": v["Severity"],
        }
        for result in report.get("Results", [])
        for v in result.get("Vulnerabilities") or []
    ]
    os_meta = report.get("Metadata", {}).get("OS", {})
    return {
        "image": image,
        "os": f"{os_meta.get('Family', '?')} {os_meta.get('Name', '?')}",
        "os_end_of_support": bool(os_meta.get("EOSL")),
        "vulnerabilities": vulns,
    }


@collector("image_vulnerabilities", requires="docker")
def image_vulnerabilities(ctx: Context, asset: DockerTarget) -> dict:
    images = sorted({s["image"] for s in ctx.collect("docker_services", asset)["services"]})
    if not images:
        raise CollectorError("no running containers to scan")
    return {
        "scanner": TRIVY_IMAGE,
        "images": [_trivy(image) for image in images],
        "risk_exceptions": _risk_exceptions(ctx),
    }


def _risk_exceptions(ctx: Context) -> list[dict]:
    """Accepted vulnerability risks from the organisation's exception register, if any."""
    docs = ctx.target.documents
    if not docs or not docs.risk_exceptions:
        return []
    path = docs.dir / docs.risk_exceptions
    if not path.exists():
        return []
    entries = yaml.safe_load(path.read_text()).get("exceptions") or []
    return [{**e, "expires": str(e["expires"])} for e in entries]
