"""Render a scan run as a self-contained HTML report plus a machine-readable JSON file."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from jinja2 import Environment, PackageLoader, StrictUndefined, select_autoescape

from nis2scan.report.data import ReportData

_env = Environment(
    loader=PackageLoader("nis2scan.report", "templates"),
    autoescape=select_autoescape(["html", "j2"]),
    undefined=StrictUndefined,
)


def load_narrative(run_dir: Path) -> dict | None:
    path = run_dir / "narrative.json"
    return json.loads(path.read_text()) if path.exists() else None


def render(data: ReportData, run_dir: Path) -> tuple[Path, Path]:
    narrative = load_narrative(run_dir)
    explanations = (
        {g["requirement_id"]: g for g in narrative["narrative"]["gaps"]}
        if narrative and narrative["status"] == "accepted"
        else {}
    )
    html = _env.get_template("report.html.j2").render(
        d=data, narrative=narrative, explanations=explanations
    )
    html_path = run_dir / "report.html"
    html_path.write_text(html, encoding="utf-8")

    json_path = run_dir / "report.json"
    body = asdict(data) | {"narrative": narrative}
    json_path.write_text(json.dumps(body, indent=2, default=str) + "\n")
    return html_path, json_path
