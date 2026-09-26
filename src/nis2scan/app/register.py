"""The evidence register as the app shows and edits it (ADR 0007).

The consultant records each document review here: which requirement, which documents,
the verdict, who reviewed it and why. The app writes the same YAML the scanner reads,
and appends to it rather than rewriting it, so the reviewer's comments survive.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import yaml
from pydantic import ValidationError

from nis2scan.app import workspace as ws
from nis2scan.catalog import load_requirements
from nis2scan.collectors.evidence import evidence_register as collect_register
from nis2scan.config import Target
from nis2scan.evidence import Review, decide, template
from nis2scan.registry import CHECKS, Context, load_all

DEFAULT_NAME = "evidence-register.yaml"


def _unchecked():
    load_all()
    checked = {r for c in CHECKS.values() for r in c.meta.requirements}
    requirements = load_requirements(ws.CATALOG)
    return requirements, checked


def documents(target: Target) -> list[str]:
    """Files in the documents folder, relative to it, for choosing reviewed documents."""
    return ws.files(target.documents.dir, str(target.documents.dir))


def state(folder: Path) -> dict:
    """The register's reviews with what each one currently supports, and what can be reviewed."""
    target = ws.target(folder)
    if not target.documents:
        raise ws.WorkspaceError("choose the documents folder first")
    requirements, checked = _unchecked()
    open_reqs = [
        {
            "id": r.id,
            "title": r.title,
            "article": r.source.nis2_article,
            "kind": r.testability.value,
        }
        for r in sorted(requirements, key=lambda r: r.id)
        if r.id not in checked
    ]
    docs = target.documents
    out = {
        "register": docs.evidence_register,
        "exists": bool(docs.evidence_register and (docs.dir / docs.evidence_register).is_file()),
        "requirements": open_reqs,
        "documents": documents(target),
        "reviews": [],
        "problems": [],
    }
    if not out["exists"]:
        return out
    try:
        register = collect_register(Context(target), docs)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        out["problems"] = [f"the register cannot be read: {exc}"]
        return out
    titles = {r["id"]: r["title"] for r in open_reqs}
    for review in register["reviews"]:
        decision = decide(review, ws.today())
        out["reviews"].append(
            review
            | {
                "title": titles.get(review["requirement"], ""),
                "applies": review["requirement"] in titles,
                "counts_as": decision.verdict.value,
                "reason": decision.reason,
            }
        )
    out["problems"] = register["problems"]
    return out


def create(folder: Path) -> str:
    """Start a register from the catalog template and point the target at it."""
    raw = ws.read_raw(folder)
    docs = raw.get("documents")
    if not docs or not docs.get("dir"):
        raise ws.WorkspaceError("choose the documents folder first")
    name = docs.get("evidence_register") or DEFAULT_NAME
    path = ws.target(folder).documents.dir / name
    if not path.exists():
        requirements, checked = _unchecked()
        path.write_text(template(requirements, checked))
    docs["evidence_register"] = name
    if problems := ws.save_raw(folder, raw):
        raise ws.WorkspaceError(problems[0]["message"])
    return name


def add_review(folder: Path, entry: dict) -> None:
    """Append one review, after the same validation the scanner applies."""
    target = ws.target(folder)
    docs = target.documents
    if not (docs and docs.evidence_register):
        raise ws.WorkspaceError("start an evidence register first")
    entry = {k: v for k, v in entry.items() if v not in ("", None, [])}
    try:
        review = Review.model_validate(entry)
    except ValidationError as exc:
        raise ws.WorkspaceError(
            "; ".join(
                f"{'.'.join(map(str, e['loc'])) or 'review'}: {e['msg'].removeprefix('Value error, ')}"
                for e in exc.errors()
            )
        ) from None
    requirements, checked = _unchecked()
    if review.requirement not in {r.id for r in requirements}:
        raise ws.WorkspaceError(f"{review.requirement} is not in the catalog")
    if review.requirement in checked:
        raise ws.WorkspaceError(f"{review.requirement} is covered by automated checks")
    missing = [d for d in review.documents if not (docs.dir / d).is_file()]
    if missing:
        raise ws.WorkspaceError(f"document not found: {', '.join(missing)}")
    path = docs.dir / docs.evidence_register
    text = path.read_text() if path.exists() else "reviews:\n"
    existing = (yaml.safe_load(text) or {}).get("reviews") or []
    if any(r.get("requirement") == review.requirement for r in existing if isinstance(r, dict)):
        raise ws.WorkspaceError(
            f"{review.requirement} is already reviewed in the register; "
            "two reviews of one requirement would cancel each other"
        )
    record = review.model_dump(mode="json", exclude_none=True)
    _append(path, text, record, len(existing))


def _append(path: Path, text: str, record: dict, count: int) -> None:
    items = re.findall(r"^([ \t]*)- requirement:", text, flags=re.MULTILINE)
    indent = items[0] if items else "  "
    block = yaml.safe_dump([record], sort_keys=False, allow_unicode=True, width=88)
    block = "".join(indent + line if line.strip() else line for line in block.splitlines(True))
    candidate = text.rstrip("\n") + "\n" + block
    try:
        parsed = (yaml.safe_load(candidate) or {}).get("reviews") or []
        ok = len(parsed) == count + 1 and parsed[-1]["requirement"] == record["requirement"]
    except yaml.YAMLError:
        ok = False
    if not ok:  # an unusual layout: rewrite the file as data, keeping a copy of the original
        shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
        data = yaml.safe_load(text) or {}
        data["reviews"] = [*(data.get("reviews") or []), record]
        candidate = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    path.write_text(candidate)
