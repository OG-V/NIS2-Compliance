"""Document evidence: requirements judged by a person's review of the organisation's documents.

Most of NIS2 is organisational: policies, training, supplier management, procedures.
No automated check can judge whether a policy is adequate, and no model may (ADR 0001).
A named reviewer, typically the consultant, judges it and records the decision in the
evidence register. The tool does not judge documents. It verifies and records the
decision (ADR 0007):

- every referenced document exists, and its SHA-256 is recorded, so a later change is
  visible;
- the review names a reviewer, a date and a written rationale;
- a review applies only to a requirement in the catalog that no automated check covers
  (a document cannot overrule a failing check);
- a review dated after the scan, one past its `valid_until`, or one whose document is
  missing makes the requirement "not assessed", never a pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Literal

from pydantic import BaseModel, Field, model_validator

from nis2scan.models import Verdict


class Review(BaseModel):
    """One entry of the evidence register, as the reviewer writes it."""

    requirement: str
    documents: list[str] = []  # paths relative to the documents folder
    verdict: Literal["evidenced", "partially_evidenced", "not_satisfied"]
    reviewed_by: str = Field(min_length=1)  # name and role
    reviewed_on: date
    rationale: str = Field(min_length=1)
    valid_until: date | None = None  # when the review must be repeated, if ever

    @model_validator(mode="after")
    def _documents_back_a_positive_verdict(self):
        if self.verdict != "not_satisfied" and not self.documents:
            raise ValueError("an evidenced verdict needs at least one reviewed document")
        return self


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    review: dict  # the register entry, with document hashes


def decide(review: dict, today: date) -> Decision:
    """The verdict a recorded review supports on `today`."""
    missing = [d["path"] for d in review["documents"] if d["sha256"] is None]
    reviewed_on = date.fromisoformat(review["reviewed_on"])
    valid_until = date.fromisoformat(review["valid_until"]) if review.get("valid_until") else None
    if missing:
        return Decision(
            Verdict.NOT_ASSESSED, f"reviewed document not found: {', '.join(missing)}", review
        )
    if reviewed_on > today:
        return Decision(Verdict.NOT_ASSESSED, f"review dated {reviewed_on}, after the scan", review)
    if valid_until and valid_until < today:
        return Decision(Verdict.NOT_ASSESSED, f"document review expired on {valid_until}", review)
    return Decision(
        Verdict(review["verdict"]),
        f"document review by {review['reviewed_by']} on {reviewed_on}: {review['rationale']}",
        review,
    )


def apply(
    register: dict, known: set[str], checked: set[str], today: date
) -> tuple[dict[str, Decision], list[str]]:
    """Decisions per requirement, and the register's problems (entries not applied)."""
    problems = list(register.get("problems", []))
    counts: dict[str, int] = {}
    for review in register["reviews"]:
        counts[review["requirement"]] = counts.get(review["requirement"], 0) + 1
    decisions = {}
    for review in register["reviews"]:
        req = review["requirement"]
        if req not in known:
            problems.append(f"{req}: not a requirement in the catalog")
        elif req in checked:
            problems.append(
                f"{req}: covered by automated checks, so a document review does not apply"
            )
        elif counts[req] > 1:
            problems.append(f"{req}: reviewed more than once in the register; none applied")
        else:
            decisions[req] = decide(review, today)
    return decisions, list(dict.fromkeys(problems))


def template(requirements, checked: set[str]) -> str:
    """A register to fill in: every requirement no check covers, grouped by NIS2 measure.

    Entries are commented out, so the file is valid as it stands and a reviewer
    uncomments only what they have actually reviewed.
    """
    lines = [
        "# Evidence register: requirements judged by reviewing the organisation's documents.",
        "# Uncomment an entry (remove the leading '# ' from its lines) once you have reviewed",
        "# it, and fill it in. nis2scan verifies and records your",
        "# decision (ADR 0007): documents must exist (they are hashed), and a review that has",
        "# expired or is dated after the scan counts as not assessed.",
        "#   verdict: evidenced | partially_evidenced | not_satisfied",
        "#   documents: paths relative to this file; may be empty only for not_satisfied",
        "reviews:",
    ]
    open_reqs = [r for r in requirements if r.id not in checked]
    by_article: dict[str, list] = {}
    for r in open_reqs:
        by_article.setdefault(r.source.nis2_article, []).append(r)
    for article in sorted(by_article):
        lines += ["", f"# --- NIS2 Art. {article} ---"]
        for r in sorted(by_article[article], key=lambda r: r.id):
            quote = " ".join(r.source.quote.split())
            quote = quote if len(quote) <= 110 else quote[:107].rstrip() + "..."
            lines += [
                f"# - requirement: {r.id}",
                f"#   # {r.title} ({r.testability.value}; {r.source.provision})",
                f'#   # "{quote}"',
                "#   documents: []",
                "#   verdict:",
                "#   reviewed_by:",
                "#   reviewed_on:",
                "#   valid_until:",
                "#   rationale:",
            ]
    return "\n".join(lines) + "\n"
