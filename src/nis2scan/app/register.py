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


def _validated(folder: Path, entry: dict) -> tuple[Review, Path]:
    """A review checked as the scanner would check it, and the register's path."""
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
    return review, docs.dir / docs.evidence_register


def _register(path: Path) -> tuple[str, list[dict]]:
    text = path.read_text() if path.exists() else "reviews:\n"
    reviews = (yaml.safe_load(text) or {}).get("reviews") or []
    return text, [r for r in reviews if isinstance(r, dict)]


def _ids(reviews: list[dict]) -> list[str]:
    return [r.get("requirement") for r in reviews]


def add_review(folder: Path, entry: dict) -> None:
    """Append one review, after the same validation the scanner applies."""
    review, path = _validated(folder, entry)
    text, existing = _register(path)
    if review.requirement in _ids(existing):
        raise ws.WorkspaceError(
            f"{review.requirement} is already reviewed in the register; "
            "two reviews of one requirement would cancel each other"
        )
    record = review.model_dump(mode="json", exclude_none=True)
    items = re.findall(r"^([ \t]*)- requirement:", text, flags=re.MULTILINE)
    candidate = text.rstrip("\n") + "\n" + _block(record, items[0] if items else "  ")
    _write(path, text, candidate, [*existing, record], record)


def update_review(folder: Path, requirement: str, entry: dict) -> None:
    """Replace the review of `requirement`, e.g. after a new document or a new review date."""
    review, path = _validated(folder, entry)
    if review.requirement != requirement:
        raise ws.WorkspaceError(
            "a review cannot move to another requirement: delete it and record a new one"
        )
    text, existing = _register(path)
    if requirement not in _ids(existing):
        raise ws.WorkspaceError(f"{requirement} has no review in the register")
    record = review.model_dump(mode="json", exclude_none=True)
    expected = [record if r.get("requirement") == requirement else r for r in existing]
    _write(path, text, _replace(text, requirement, record), expected, record)


def delete_review(folder: Path, requirement: str) -> None:
    """Remove the review of `requirement`; the next scan reports it as not assessed."""
    docs = ws.target(folder).documents
    if not (docs and docs.evidence_register):
        raise ws.WorkspaceError("there is no evidence register")
    path = docs.dir / docs.evidence_register
    text, existing = _register(path)
    if requirement not in _ids(existing):
        raise ws.WorkspaceError(f"{requirement} has no review in the register")
    expected = [r for r in existing if r.get("requirement") != requirement]
    _write(path, text, _replace(text, requirement, None), expected)


def _block(record: dict, indent: str) -> str:
    block = yaml.safe_dump([record], sort_keys=False, allow_unicode=True, width=88)
    return "".join(indent + line if line.strip() else line for line in block.splitlines(True))


def _replace(text: str, requirement: str, record: dict | None) -> str | None:
    """The register with one entry's lines replaced (or removed); None if it cannot be found.

    An entry runs from its `- requirement:` line to the next line indented no deeper than
    that line (the next entry, a comment or the next key). Other lines are kept as written.
    """
    lines = text.splitlines(True)
    head = re.compile(rf"^([ \t]*)- requirement:\s*['\"]?{re.escape(requirement)}['\"]?\s*$")
    for i, line in enumerate(lines):
        if match := head.match(line):
            indent = match.group(1)
            j = i + 1
            while j < len(lines):
                stripped = lines[j].strip()
                if stripped and len(lines[j]) - len(lines[j].lstrip()) <= len(indent):
                    break
                j += 1
            while j - 1 > i and not lines[j - 1].strip():  # trailing blank lines stay
                j -= 1
            new = _block(record, indent) if record else ""
            return "".join(lines[:i]) + new + "".join(lines[j:])
    return None


def _write(path: Path, text: str, candidate: str | None, expected: list[dict], record=None):
    """Write `candidate` if it parses to the expected reviews; else rewrite the file as data."""
    ok = False
    if candidate is not None:
        try:
            parsed = [
                r
                for r in (yaml.safe_load(candidate) or {}).get("reviews") or []
                if isinstance(r, dict)
            ]
            ok = _ids(parsed) == _ids(expected)
            if ok and record:
                mine = next(r for r in parsed if r["requirement"] == record["requirement"])
                ok = (
                    Review.model_validate(mine).model_dump(mode="json", exclude_none=True) == record
                )
        except (yaml.YAMLError, ValidationError):
            ok = False
    if not ok:  # an unusual layout: rewrite the file as data, keeping a copy of the original
        if path.exists():
            shutil.copy2(path, path.with_suffix(path.suffix + ".bak"))
        data = yaml.safe_load(text) or {}
        data["reviews"] = expected
        candidate = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    path.write_text(candidate)
