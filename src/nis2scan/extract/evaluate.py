"""Deterministic evaluation of extracted requirements against a hand-labelled gold set.

No LLM grades the output. Each metric is a plain rule that anyone can re-run and
argue with:

- quote validity: the quote appears verbatim in the cited provision.
- obligation recall: each gold obligation's keywords all appear in the obligation
  or quote of at least one accepted requirement.
- granularity: the number of requirements falls inside the gold range.
- testability accuracy: the label is one of the gold-accepted labels.
- invented specificity: numbers, durations, frequencies or crypto/standard names
  that appear in the output but not in the provision text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import BaseModel

from nis2scan.extract.verify import SourceIndex, check_quote, normalise
from nis2scan.models import Requirement, ReviewStatus

SPECIFIC = re.compile(
    r"\b(\d+(?:[.,]\d+)?|days?|hours?|weeks?|months?|years?|annually|monthly|weekly|daily|"
    r"quarterly|aes|rsa|sha-?\d*|tls|ssl|iso|nist|cis|fips|bits?)\b",
    re.IGNORECASE,
)


class GoldObligation(BaseModel):
    keywords: list[str]  # all must appear (case-insensitive) in obligation + quote


class GoldProvision(BaseModel):
    testability: list[str]
    count: tuple[int, int]  # inclusive range of acceptable requirement counts
    obligations: list[GoldObligation]


class GoldSet(BaseModel):
    labelled_by: str
    status: str
    provisions: dict[str, GoldProvision]


def load_gold(path: Path) -> GoldSet:
    return GoldSet.model_validate(yaml.safe_load(path.read_text()))


def invented_terms(req: Requirement, provision_text: str) -> list[str]:
    """Specific-looking terms in the requirement that the provision text never uses."""
    source = normalise(provision_text).lower()
    output = " ".join(
        [
            req.obligation,
            *req.evidence,
            *(v for v in req.parameters.values() if v != "entity_defined"),
        ]
    )
    terms = {m.group(0).lower() for m in SPECIFIC.finditer(output)}
    return sorted(t for t in terms if not re.search(rf"\b{re.escape(t)}\b", source))


@dataclass
class ProvisionScore:
    number: str
    extracted: int
    quotes_valid: int
    accepted: int
    count_ok: bool
    obligations_found: int
    obligations_total: int
    testability_ok: int
    invented: dict[str, list[str]] = field(default_factory=dict)
    missed: list[list[str]] = field(default_factory=list)


def score_provision(
    number: str, gold: GoldProvision, reqs: list[Requirement], index: SourceIndex
) -> ProvisionScore:
    valid = [r for r in reqs if check_quote(r, index).ok]
    accepted = [r for r in valid if r.review.status != ReviewStatus.REJECTED]
    text = index.provision_text(reqs[0].source.instrument, reqs[0].source.provision) if reqs else ""

    haystacks = [normalise(f"{r.obligation} {r.source.quote}").lower() for r in accepted]
    missed = [
        o.keywords
        for o in gold.obligations
        if not any(all(k.lower() in h for k in o.keywords) for h in haystacks)
    ]
    invented = {r.id: terms for r in reqs if (terms := invented_terms(r, text))}
    return ProvisionScore(
        number=number,
        extracted=len(reqs),
        quotes_valid=len(valid),
        accepted=len(accepted),
        count_ok=gold.count[0] <= len(accepted) <= gold.count[1],
        obligations_found=len(gold.obligations) - len(missed),
        obligations_total=len(gold.obligations),
        testability_ok=sum(r.testability in gold.testability for r in accepted),
        invented=invented,
        missed=missed,
    )


def load_extracted(directory: Path) -> dict[str, list[Requirement]]:
    """Requirements under a directory, grouped by Annex point number."""
    grouped: dict[str, list[Requirement]] = {}
    for file in sorted(directory.rglob("*.yaml")):
        req = Requirement.model_validate(yaml.safe_load(file.read_text()))
        match = re.fullmatch(r"Annex, point (.+)", req.source.provision)
        if match:
            grouped.setdefault(match.group(1), []).append(req)
    return grouped


@dataclass
class Evaluation:
    scores: list[ProvisionScore]
    not_extracted: list[str]

    def summary(self) -> dict[str, float | int]:
        s = self.scores
        extracted = sum(p.extracted for p in s)
        accepted = sum(p.accepted for p in s)

        def ratio(num: int, den: int) -> float:
            return round(num / den, 3) if den else 0.0

        return {
            "provisions_scored": len(s),
            "provisions_missing": len(self.not_extracted),
            "requirements_extracted": extracted,
            "quote_validity": ratio(sum(p.quotes_valid for p in s), extracted),
            "obligation_recall": ratio(
                sum(p.obligations_found for p in s), sum(p.obligations_total for p in s)
            ),
            "granularity_in_range": ratio(sum(p.count_ok for p in s), len(s)),
            "testability_accuracy": ratio(sum(p.testability_ok for p in s), accepted),
            "invented_specificity_rate": ratio(sum(len(p.invented) for p in s), extracted),
        }


def evaluate(directory: Path, gold: GoldSet, index: SourceIndex) -> Evaluation:
    extracted = load_extracted(directory)
    scores = [
        score_provision(number, g, extracted[number], index)
        for number, g in gold.provisions.items()
        if number in extracted
    ]
    missing = [n for n in gold.provisions if n not in extracted]
    return Evaluation(scores, missing)
