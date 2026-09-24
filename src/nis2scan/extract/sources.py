"""Legal source texts: fetch from EUR-Lex, normalise to plain text, split into provisions.

The stored plain-text files in sources/ are the ground truth for quote
verification. Their SHA-256 is recorded in sources/manifest.json and in every
extracted requirement, so a changed source makes stale extractions visible.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

EURLEX_URL = "https://eur-lex.europa.eu/legal-content/EN/TXT/HTML/?uri=CELEX:{celex}"
# EUR-Lex's bot protection rejects minimal user agents.
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0 Safari/537.36"
)

NUMBER = re.compile(r"\d+(\.\d+)*\.")
LETTER = re.compile(r"\([a-z]+\)")


@dataclass(frozen=True)
class Source:
    key: str
    celex: str
    instrument: str
    filename: str

    @property
    def url(self) -> str:
        return EURLEX_URL.format(celex=self.celex)


NIS2 = Source("nis2", "32022L2555", "Directive (EU) 2022/2555", "nis2-2022-2555.txt")
CIR_2690 = Source(
    "cir2690",
    "32024R2690",
    "Commission Implementing Regulation (EU) 2024/2690",
    "cir-2024-2690-annex.txt",
)
SOURCES = {s.key: s for s in (NIS2, CIR_2690)}
BY_INSTRUMENT = {s.instrument: s for s in SOURCES.values()}


def html_to_lines(raw: str) -> list[str]:
    """One line per HTML text node, whitespace-collapsed."""
    raw = re.sub(r"<(script|style)[^>]*>.*?</\1>", "", raw, flags=re.DOTALL | re.IGNORECASE)
    text = html.unescape(re.sub(r"<[^>]+>", "\n", raw))
    return [re.sub(r"\s+", " ", line).strip() for line in text.splitlines() if line.strip()]


def _until_footer(lines: list[str]) -> list[str]:
    end = next((i for i, line in enumerate(lines) if line.startswith("ELI:")), len(lines))
    return lines[:end]


def _join_markers(lines: list[str]) -> list[str]:
    """Merge '1.1.1.' / '(a)' marker lines with the text line that follows them."""
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if (NUMBER.fullmatch(line) or LETTER.fullmatch(line)) and i + 1 < len(lines):
            if NUMBER.fullmatch(line):
                out.append("")  # blank line before each numbered point
            out.append(f"{line} {lines[i + 1]}")
            i += 2
        else:
            out.append(line)
            i += 1
    return out


def normalise_source(source: Source, raw_html: str) -> str:
    lines = _until_footer(html_to_lines(raw_html))
    if source is CIR_2690:
        lines = lines[lines.index("ANNEX") :]
    else:
        start = next(
            i for i, line in enumerate(lines) if line.startswith("DIRECTIVE (EU) 2022/2555")
        )
        lines = lines[start:]
    return "\n".join(_join_markers(lines)).strip() + "\n"


def fetch(source: Source, sources_dir: Path) -> dict:
    req = urllib.request.Request(source.url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        raw = resp.read().decode("utf-8")
    if not raw:
        raise RuntimeError(f"EUR-Lex returned an empty page for {source.celex}; retry later")
    text = normalise_source(source, raw)
    path = sources_dir / source.filename
    path.write_text(text, encoding="utf-8")
    return {
        "instrument": source.instrument,
        "celex": source.celex,
        "url": source.url,
        "file": source.filename,
        "sha256": sha256(path),
        "retrieved": datetime.now(UTC).date().isoformat(),
    }


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_manifest(sources_dir: Path, entries: dict[str, dict]) -> None:
    path = sources_dir / "manifest.json"
    path.write_text(json.dumps(entries, indent=2, sort_keys=True) + "\n")


def read_text(source: Source, sources_dir: Path) -> str:
    path = sources_dir / source.filename
    if not path.exists():
        raise FileNotFoundError(f"{path} missing; run `nis2scan fetch-sources`")
    return path.read_text(encoding="utf-8")


@dataclass(frozen=True)
class Provision:
    number: str  # e.g. "11.7.1"
    section: str  # e.g. "11. Access control (Article 21(2), points (i) and (j), ...)"
    subsection: str  # e.g. "11.7. Authentication"
    text: str  # full text including lettered sub-points, one per line
    nis2_points: tuple[str, ...]  # Art. 21(2) points the section implements, e.g. ("i", "j")

    @property
    def nis2_article(self) -> str:
        return "21(2)(" + "), (".join(self.nis2_points) + ")"


def _nis2_points(section_title: str) -> tuple[str, ...]:
    match = re.search(r"Article 21\(2\), points? (.+?) of Directive", section_title)
    return tuple(re.findall(r"\(([a-j])\)", match.group(1))) if match else ()


def parse_annex(text: str) -> list[Provision]:
    """Split the normalised Annex into its numbered provisions.

    Most sections are organised as x.y (subsection heading) and x.y.z
    (provision). Sections without subsections (7 and 9) number their
    provisions x.y directly.
    """
    numbers = re.findall(r"^(\d+(?:\.\d+)*)\. ", text, flags=re.MULTILINE)
    has_subsections = {n.split(".")[0] for n in numbers if n.count(".") == 2}
    provisions: list[Provision] = []
    section = subsection = ""
    current: list[str] | None = None
    number = ""

    def flush():
        if current is not None:
            provisions.append(
                Provision(
                    number=number,
                    section=section,
                    subsection=subsection,
                    text="\n".join(current),
                    nis2_points=_nis2_points(section),
                )
            )

    for line in text.splitlines():
        match = re.match(r"(\d+(?:\.\d+)*)\. (.*)", line)
        if match:
            depth = match.group(1).count(".")
            if depth == 0:
                flush()
                current, section = None, line
            elif depth == 1 and match.group(1).split(".")[0] in has_subsections:
                flush()
                current, subsection = None, line
            elif depth == 1:
                flush()
                subsection = ""
                number, current = match.group(1), [match.group(2)]
            else:
                flush()
                number, current = match.group(1), [match.group(2)]
        elif current is not None and line:
            current.append(line)
    flush()
    return provisions


def article_text(text: str, article: int) -> str:
    """Text of one Directive article: from 'Article n' to 'Article n+1' (first occurrences)."""
    lines = text.splitlines()
    start = lines.index(f"Article {article}")
    end = lines.index(f"Article {article + 1}", start + 1)
    return "\n".join(lines[start:end])
