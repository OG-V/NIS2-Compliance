"""The evidence register: document reviews recorded by a named reviewer (ADR 0007)."""

import hashlib
from typing import Any

import yaml
from pydantic import ValidationError

from nis2scan.config import DocumentsTarget
from nis2scan.evidence import Review
from nis2scan.registry import Context, NotApplicable, collector


def _sha256(path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


@collector("evidence_register", requires="documents")
def evidence_register(ctx: Context, docs: DocumentsTarget) -> dict[str, Any]:
    """The register's reviews, each document hashed. Malformed entries become problems."""
    if not docs.evidence_register:
        raise NotApplicable("no evidence register given")
    path = docs.dir / docs.evidence_register
    raw = yaml.safe_load(path.read_text()) or {}
    reviews, problems = [], []
    for number, entry in enumerate(raw.get("reviews") or [], 1):
        try:
            review = Review.model_validate(entry)
        except ValidationError as exc:
            where = (
                entry.get("requirement", f"entry {number}")
                if isinstance(entry, dict)
                else f"entry {number}"
            )
            problems.append(f"{where}: {exc.errors()[0]['msg']}")
            continue
        reviews.append(
            review.model_dump(mode="json")
            | {
                "documents": [
                    {"path": d, "sha256": _sha256(docs.dir / d)} for d in review.documents
                ]
            }
        )
    return {
        "register": docs.evidence_register,
        "sha256": _sha256(path),
        "reviews": reviews,
        "problems": problems,
    }
