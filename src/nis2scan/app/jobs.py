"""Long-running work in the background, with progress events the interface polls.

Each job runs in a thread and appends events ({"type": ..., ...}) as it goes; the
interface asks for the events after the last one it has seen. The work itself is the
scanner's own code: the app adds progress reporting, not a second implementation.
"""

from __future__ import annotations

import json
import os
import threading
import time
import traceback
import uuid
from dataclasses import asdict
from pathlib import Path

from nis2scan.app import workspace as ws
from nis2scan.catalog import load_requirements
from nis2scan.config import ASSET_SECTIONS, Target, load_profile, parse_env_file
from nis2scan.onboarding import authorisation, plan
from nis2scan.registry import CHECKS, COLLECTORS, Context, load_all

# What each collector does, as the progress view says it.
ACTIVITY = {
    "asset_inventory": "Reading the asset inventory",
    "backup_detect": "Identifying the backup product",
    "backup_snapshots": "Reading backup history",
    "docker_services": "Listing container services",
    "evidence_register": "Verifying the evidence register",
    "http_probe": "Checking HTTP security headers",
    "idp_config": "Reading identity policies",
    "idp_default_admin": "Testing for a default admin password",
    "idp_detect": "Identifying the identity product",
    "image_vulnerabilities": "Scanning container images for vulnerabilities",
    "ir_plan": "Reading the incident response plan",
    "log_retention": "Measuring log retention",
    "logs_detect": "Identifying the log store",
    "ssh_auth_methods": "Checking SSH authentication methods",
    "sshd_effective_config": "Reading the effective SSH configuration",
    "tls_probe": "Testing TLS versions and certificates",
}


class Job:
    def __init__(self, kind: str):
        self.id = uuid.uuid4().hex[:12]
        self.kind = kind
        self.state = "running"  # running | done | failed
        self.events: list[dict] = []
        self.result: dict | None = None
        self.error: str | None = None
        self.started = time.time()
        self._lock = threading.Lock()

    def emit(self, **event) -> None:
        with self._lock:
            self.events.append({"t": round(time.time() - self.started, 2), **event})

    def view(self, since: int = 0) -> dict:
        with self._lock:
            return {
                "id": self.id,
                "kind": self.kind,
                "state": self.state,
                "events": self.events[since:],
                "next": len(self.events),
                "result": self.result,
                "error": self.error,
            }


JOBS: dict[str, Job] = {}


def start(kind: str, work, *args) -> Job:
    job = Job(kind)
    JOBS[job.id] = job

    def run():
        try:
            job.result = work(job, *args)
            job.state = "done"
        except ws.WorkspaceError as exc:
            job.error, job.state = str(exc), "failed"
        except Exception as exc:  # noqa: BLE001 - shown to the consultant, logged in full
            traceback.print_exc()
            job.error, job.state = f"{type(exc).__name__}: {exc}", "failed"

    threading.Thread(target=run, daemon=True, name=f"job-{kind}").start()
    return job


def busy() -> bool:
    return any(j.state == "running" for j in JOBS.values())


# --- access check -------------------------------------------------------------------------------


def _only(target: Target, section: str, asset) -> Target:
    """The target reduced to one asset, so each system can be probed and reported in turn."""
    empty = {s: [] for s in ASSET_SECTIONS} | {"documents": None}
    value = asset if section == "documents" else [asset]
    return target.model_copy(update=empty | {section: value})


def check_access(job: Job, folder: Path) -> dict:
    target = ws.target(folder)
    auth = authorisation(target, ws.today())
    job.emit(type="authorisation", access=asdict(auth))
    pending = [(s, a) for s in (*ASSET_SECTIONS, "documents") for a in target.assets(s)]
    job.emit(type="plan", total=len(pending), systems=[[s, a.name] for s, a in pending])
    systems = []
    for section, asset in pending:
        job.emit(type="probing", section=section, name=asset.name)
        (system,) = plan(_only(target, section, asset), probe=True)
        row = asdict(system) | {"kind": system.kind, "ready": system.ready}
        systems.append(row)
        job.emit(type="system", system=row)
    return {
        "authorisation": asdict(auth),
        "systems": systems,
        "ready": auth.status == "ok" and all(s["ready"] for s in systems),
    }


# --- scan ---------------------------------------------------------------------------------------


class ProgressContext(Context):
    """The scanner's context, reporting each collector as it starts and finishes."""

    def __init__(self, target: Target, job: Job, total: int):
        super().__init__(target)
        self.job, self.total, self.done = job, total, 0

    def _run(self, name, asset):
        label = ACTIVITY.get(name, name.replace("_", " "))
        self.job.emit(type="collect", collector=name, asset=asset.name, label=label)
        try:
            evidence = super()._run(name, asset)
        except Exception as exc:
            self.done += 1
            self.job.emit(
                type="collected", collector=name, asset=asset.name, ok=False,
                note=str(exc)[:200], done=self.done, total=self.total,
            )  # fmt: skip
            raise
        self.done += 1
        self.job.emit(
            type="collected", collector=name, asset=asset.name, ok=True,
            done=self.done, total=self.total,
        )  # fmt: skip
        return evidence


def _expected_collections(target: Target) -> int:
    pairs = set()
    for chk in CHECKS.values():
        col = COLLECTORS[chk.collector]
        if col.active and not target.active_tests_allowed:
            continue
        for asset in target.assets(col.requires):
            if all(getattr(asset, f, None) for f in col.needs):
                pairs.add((chk.collector, asset.name))
    for section in ASSET_SECTIONS:
        if f"{section}_detect" in COLLECTORS:
            pairs |= {(f"{section}_detect", a.name) for a in target.assets(section)}
    if target.documents and target.documents.evidence_register:
        pairs.add(("evidence_register", target.documents.name))
    return max(len(pairs), 1)


def scan(job: Job, folder: Path, make_context=ProgressContext) -> dict:
    from nis2scan.report.data import load_run
    from nis2scan.report.render import render
    from nis2scan.scan import NotAuthorised, run_scan, write_results

    load_all()
    target = ws.target(folder)
    if target.engagement is None:
        raise ws.WorkspaceError("record the client's authorisation before scanning")
    requirements = load_requirements(ws.CATALOG)
    total = _expected_collections(target)
    job.emit(type="start", total=total, target=target.name)
    ctx = make_context(target, job, total)
    try:
        result = run_scan(target, load_profile(ws.PROFILE), requirements, context=ctx)
    except NotAuthorised as exc:
        raise ws.WorkspaceError(f"Scan refused: {exc}") from None
    job.emit(type="stage", label="Writing findings and evidence")
    run = write_results(result, folder / ws.RESULTS, ws.PROFILE)
    job.emit(type="stage", label="Building the report")
    data = load_run(run)
    render(data, run)
    return summary(data, run)


def summary(data, run: Path) -> dict:
    return {
        "run": run.name,
        "target": data.target,
        "started_at": data.started_at,
        "checks": data.check_counts,
        "verdicts": data.verdict_counts,
        "by_basis": data.evidence_by_basis,
        "gaps": [
            {"title": g.title, "severity": g.severity, "topic": g.topic, "action": g.action}
            for g in data.gaps[:6]
        ],
        "gap_count": len(data.gaps),
    }


# --- AI steps (optional) -----------------------------------------------------------------------------


def api_key() -> str | None:
    """The Anthropic API key: from the environment, or saved in the app's settings."""
    if key := os.environ.get("ANTHROPIC_API_KEY"):
        return key
    path = ws.CONFIG_DIR / "anthropic.env"
    if path.is_file():
        return parse_env_file(path.read_text()).get("ANTHROPIC_API_KEY")
    return None


def save_api_key(key: str) -> None:
    key = key.strip()
    if not key or "\n" in key:
        raise ws.WorkspaceError("paste the key on one line")
    ws.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    path = ws.CONFIG_DIR / "anthropic.env"
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    path.write_text(f"ANTHROPIC_API_KEY={key}\n")


def _client():
    try:
        import anthropic
    except ImportError:
        raise ws.WorkspaceError(
            "The AI features are not installed: pip install -e '.[llm]'"
        ) from None
    key = api_key()
    if not key:
        raise ws.WorkspaceError("Add an Anthropic API key in Settings to use the AI features")
    return anthropic.Anthropic(api_key=key)


def narrate(job: Job, folder: Path, run_id: str) -> dict:
    from nis2scan.report.data import load_run
    from nis2scan.report.narrate import narrate as write_narrative
    from nis2scan.report.render import render

    run = ws.run_dir(folder, run_id)
    client = _client()
    data = load_run(run)
    job.emit(type="stage", label=f"Drafting the narrative for {len(data.gaps)} gaps")
    result = write_narrative(client, data)
    (run / "narrative.json").write_text(json.dumps(asdict(result), indent=2) + "\n")
    job.emit(type="stage", label="Rebuilding the report")
    render(data, run)
    return {"status": result.status, "attempts": result.attempts, "violations": result.violations}


def suggest(job: Job, folder: Path, documents: list[str]) -> dict:
    from nis2scan.doctext import UnreadableDocument, extract_text
    from nis2scan.suggest import suggest as run_suggest

    load_all()
    target = ws.target(folder)
    if not target.documents:
        raise ws.WorkspaceError("choose the documents folder first")
    base = target.documents.dir
    checked = {r for c in CHECKS.values() for r in c.meta.requirements}
    requirements = [r for r in load_requirements(ws.CATALOG) if r.id not in checked]
    titles = {r.id: r.title for r in requirements}
    client = _client()
    out = folder / ws.SUGGESTIONS
    out.mkdir(exist_ok=True)
    results = []
    for i, rel in enumerate(documents, 1):
        path = (base / rel).resolve()
        if not path.is_relative_to(base.resolve()):
            raise ws.WorkspaceError(f"{rel} is outside the documents folder")
        job.emit(type="document", name=rel, index=i, total=len(documents))
        try:
            text = extract_text(path)
        except (OSError, UnreadableDocument) as exc:
            row = {"document": rel, "error": str(exc), "accepted": [], "rejected": []}
        else:
            r = run_suggest(client, rel, text, requirements)
            row = asdict(r) | {"document": rel}
            for s in row["accepted"]:
                s["title"] = titles.get(s["requirement_id"], "")
        (out / (rel.replace("/", "--") + ".json")).write_text(json.dumps(row, indent=2) + "\n")
        results.append(row)
        job.emit(type="suggested", name=rel, count=len(row["accepted"]), error=row.get("error"))
    return {"documents": results}
