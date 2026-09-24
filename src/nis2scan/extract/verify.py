"""Deterministic quote verification: is a requirement's quote really in the law?

A quote passes only if it appears contiguously in the specific provision it
cites. Matching ignores differences in whitespace, typographic quotes and dashes,
but nothing else: no case folding, no fuzzy matching, no ellipses.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from nis2scan.extract.sources import BY_INSTRUMENT, NIS2, article_text, parse_annex, read_text
from nis2scan.models import Requirement

TYPOGRAPHY = str.maketrans({"‘": "'", "’": "'", "‛": "'", "“": '"', "”": '"', "–": "-", "—": "-"})


class QuoteStatus(StrEnum):
    VERBATIM = "verbatim"  # found in the cited provision
    ELSEWHERE = "elsewhere"  # found in the instrument, but not in the cited provision
    NOT_FOUND = "not_found"
    UNLOCATABLE = "unlocatable"  # the cited provision could not be resolved


@dataclass(frozen=True)
class QuoteCheck:
    requirement_id: str
    status: QuoteStatus
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == QuoteStatus.VERBATIM


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).translate(TYPOGRAPHY)
    return re.sub(r"\s+", " ", text).strip()


def contains(haystack: str, quote: str) -> bool:
    quote = normalise(quote)
    return bool(quote) and quote in normalise(haystack)


class SourceIndex:
    """Resolves provision references like 'Art. 21(2)(h)' or 'Annex, point 11.7.1'."""

    def __init__(self, sources_dir: Path):
        self.dir = sources_dir
        self._texts: dict[str, str] = {}
        self._annex: dict[str, str] | None = None

    def text(self, instrument: str) -> str:
        source = BY_INSTRUMENT[instrument]
        if source.key not in self._texts:
            self._texts[source.key] = read_text(source, self.dir)
        return self._texts[source.key]

    def provision_text(self, instrument: str, provision: str) -> str:
        source = BY_INSTRUMENT[instrument]
        if source is NIS2:
            match = re.match(r"Art\. (\d+)", provision)
            if not match:
                raise LookupError(f"cannot parse article in {provision!r}")
            return article_text(self.text(instrument), int(match.group(1)))
        if self._annex is None:
            self._annex = {p.number: p.text for p in parse_annex(self.text(instrument))}
        match = re.fullmatch(r"Annex, point (\d+(?:\.\d+)+)", provision)
        if not match or match.group(1) not in self._annex:
            raise LookupError(f"no Annex provision {provision!r}")
        return self._annex[match.group(1)]


def check_quote(req: Requirement, index: SourceIndex) -> QuoteCheck:
    src = req.source
    if src.instrument not in BY_INSTRUMENT:
        return QuoteCheck(req.id, QuoteStatus.UNLOCATABLE, f"unknown instrument {src.instrument}")
    try:
        cited = index.provision_text(src.instrument, src.provision)
    except (LookupError, ValueError) as exc:
        return QuoteCheck(req.id, QuoteStatus.UNLOCATABLE, str(exc))
    if contains(cited, src.quote):
        return QuoteCheck(req.id, QuoteStatus.VERBATIM)
    if contains(index.text(src.instrument), src.quote):
        return QuoteCheck(req.id, QuoteStatus.ELSEWHERE, f"not in {src.provision}")
    return QuoteCheck(req.id, QuoteStatus.NOT_FOUND)
