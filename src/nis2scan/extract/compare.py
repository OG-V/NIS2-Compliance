"""Compare two extraction runs of the same provisions: how stable is the output?

Current Claude models don't accept a sampling temperature, so run-to-run
variation can't be switched off, only measured. Two requirements from different
runs are treated as the same clause when one quote contains the other
(normalised). That rule is deterministic and tolerates a run choosing a
slightly longer or shorter span.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from nis2scan.extract.evaluate import load_extracted
from nis2scan.extract.verify import normalise
from nis2scan.models import Requirement


def _same_clause(a: Requirement, b: Requirement) -> bool:
    qa, qb = normalise(a.source.quote), normalise(b.source.quote)
    return qa in qb or qb in qa


@dataclass
class ProvisionDiff:
    number: str
    count_a: int
    count_b: int
    matched: int  # clauses found in both runs
    testability_agree: int  # of the matched pairs

    @property
    def overlap(self) -> float:
        """Matched clauses as a share of the larger run (1.0 = same clauses)."""
        return self.matched / max(self.count_a, self.count_b, 1)


def compare_provision(number: str, a: list[Requirement], b: list[Requirement]) -> ProvisionDiff:
    remaining = list(b)
    matched = agree = 0
    for req in a:
        partner = next((r for r in remaining if _same_clause(req, r)), None)
        if partner:
            remaining.remove(partner)
            matched += 1
            agree += req.testability == partner.testability
    return ProvisionDiff(number, len(a), len(b), matched, agree)


@dataclass
class Comparison:
    diffs: list[ProvisionDiff]
    only_in_a: list[str]
    only_in_b: list[str]

    def summary(self) -> dict[str, float | int]:
        d = self.diffs
        matched = sum(x.matched for x in d)
        return {
            "provisions_compared": len(d),
            "same_count_rate": round(sum(x.count_a == x.count_b for x in d) / len(d), 3)
            if d
            else 0.0,
            "mean_clause_overlap": round(sum(x.overlap for x in d) / len(d), 3) if d else 0.0,
            "testability_agreement": round(sum(x.testability_agree for x in d) / matched, 3)
            if matched
            else 0.0,
        }


def compare(dir_a: Path, dir_b: Path) -> Comparison:
    a, b = load_extracted(dir_a), load_extracted(dir_b)
    common = sorted(set(a) & set(b), key=lambda n: [int(x) for x in n.split(".")])
    return Comparison(
        [compare_provision(n, a[n], b[n]) for n in common],
        sorted(set(a) - set(b)),
        sorted(set(b) - set(a)),
    )
