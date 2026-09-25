"""Core data model.

Three kinds of objects, created by different means (see docs/design.md §3):

- Requirement: what the law says. LLM-extracted, human-reviewed, stored as YAML.
- CheckMeta:   what our code tests. Hand-written, maps to requirements.
- Finding:     what a check observed on a target at scan time.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Testability(StrEnum):
    TECHNICAL = "technical"  # verifiable from system state
    DOCUMENTARY = "documentary"  # verifiable from a document's existence/content
    ORGANISATIONAL = "organisational"  # needs audit/interview; never automated


class ReviewStatus(StrEnum):
    DRAFT = "draft"
    REVIEWED = "reviewed"
    REJECTED = "rejected"


class SourceRef(BaseModel):
    instrument: str  # e.g. "Directive (EU) 2022/2555" or "CIR (EU) 2024/2690"
    provision: str  # e.g. "Art. 21(2)(j)" or "Annex, point 11.7.1"
    nis2_article: str  # the NIS2 article this ultimately implements, e.g. "21(2)(j)"
    quote: str  # verbatim source text; checked against sources/ by the verifier


class ExtractionMeta(BaseModel):
    model: str
    effort: str | None = (
        None  # None for runs made before effort was recorded (Opus 5 default: high)
    )
    prompt_version: str
    source_sha256: str
    extracted_at: datetime


class Review(BaseModel):
    status: ReviewStatus = ReviewStatus.DRAFT
    reviewer: str | None = None
    reviewed_at: date | None = None
    notes: str = ""


class Requirement(BaseModel):
    id: str = Field(pattern=r"^REQ-[A-Z0-9.\-]+$")
    title: str
    obligation: str  # normalised "The entity shall ..." statement
    source: SourceRef
    testability: Testability
    evidence: list[str] = []  # kinds of evidence that would demonstrate it
    # Values the law leaves open, e.g. {"retention_period": "entity_defined"}.
    # Concrete thresholds belong in the organisational profile, never here.
    parameters: dict[str, str] = {}
    extraction: ExtractionMeta | None = None  # None when hand-authored
    review: Review = Review()


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Coverage(StrEnum):
    FULL = "full"  # passing this check alone evidences the requirement
    PARTIAL = "partial"  # evidences only part of the requirement


class Effort(StrEnum):
    QUICK = "quick"  # a setting, a password or a line of configuration
    CHANGE = "change"  # a configuration or process change that needs some testing
    PROJECT = "project"  # planned work such as upgrading several systems


class CheckMeta(BaseModel):
    id: str = Field(pattern=r"^CHK-[A-Z0-9\-]+$")
    title: str
    requirements: list[str] = Field(min_length=1)
    coverage: Coverage
    severity: Severity
    severity_rationale: str  # severity is a human judgement, not extracted from law
    action: str  # what to do if the check fails, in words a manager understands
    effort: Effort  # a rough human estimate of the fix, like severity
    target_type: str


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"  # the check could not run; never counted as pass or fail
    NOT_APPLICABLE = "not_applicable"


class Finding(BaseModel):
    check_id: str
    target: str
    asset: str | None = None  # the asset checked; None when the target has none of its kind
    status: CheckStatus
    observed: dict[str, Any] = {}
    expected: dict[str, Any] = {}
    evidence_ref: str | None = None  # path/hash of raw collected evidence
    message: str = ""
    collected_at: datetime


class Verdict(StrEnum):
    EVIDENCED = "evidenced"
    PARTIALLY_EVIDENCED = "partially_evidenced"
    NOT_SATISFIED = "not_satisfied"
    NOT_ASSESSED = "not_assessed"


class RequirementVerdict(BaseModel):
    requirement_id: str
    title: str
    provision: str
    nis2_article: str
    quote: str
    testability: Testability
    review_status: ReviewStatus
    verdict: Verdict
    check_ids: list[str]
    reason: str


def rollup(checks: list[CheckMeta], findings: list[Finding]) -> Verdict:
    """Deterministically roll the findings of one requirement's checks into a verdict."""
    by_check = {c.id: c for c in checks}
    relevant = [
        f for f in findings if f.check_id in by_check and f.status != CheckStatus.NOT_APPLICABLE
    ]
    if any(f.status == CheckStatus.FAIL for f in relevant):
        return Verdict.NOT_SATISFIED
    if not relevant or any(f.status == CheckStatus.ERROR for f in relevant):
        return Verdict.NOT_ASSESSED
    if any(by_check[f.check_id].coverage == Coverage.FULL for f in relevant):
        return Verdict.EVIDENCED
    return Verdict.PARTIALLY_EVIDENCED
