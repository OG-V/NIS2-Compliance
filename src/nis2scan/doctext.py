"""Plain text from the documents a client hands over: text, Markdown, Word and PDF.

Text formats and Word (.docx, a zip of XML) need only the standard library. PDF needs
the optional `docs` extra (pypdf). Scanned PDFs without a text layer yield no text and
are reported as such, rather than sent to a model as nothing.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from xml.etree import ElementTree

TEXT_SUFFIXES = {".md", ".txt", ".yaml", ".yml", ".csv", ".json", ".rst"}
WORD_NS = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


class UnreadableDocument(Exception):
    """The document's text cannot be extracted (unsupported format, no text layer…)."""


def _docx(path: Path) -> str:
    try:
        with zipfile.ZipFile(path) as z:
            root = ElementTree.fromstring(z.read("word/document.xml"))
    except (zipfile.BadZipFile, KeyError, ElementTree.ParseError) as exc:
        raise UnreadableDocument(f"{path.name}: not a readable Word document ({exc})") from None
    paragraphs = []
    for p in root.iter(f"{WORD_NS}p"):
        text = "".join(t.text or "" for t in p.iter(f"{WORD_NS}t"))
        if text.strip():
            paragraphs.append(text)
    return "\n".join(paragraphs)


def _pdf(path: Path) -> str:
    try:
        from pypdf import PdfReader
    except ImportError:
        raise UnreadableDocument(
            "reading PDFs needs the docs extra: pip install -e '.[docs]'"
        ) from None
    return "\n".join(page.extract_text() or "" for page in PdfReader(path).pages)


def extract_text(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix in TEXT_SUFFIXES:
        text = path.read_text(encoding="utf-8", errors="replace")
    elif suffix == ".docx":
        text = _docx(path)
    elif suffix == ".pdf":
        text = _pdf(path)
    else:
        raise UnreadableDocument(f"{path.name}: unsupported format {suffix or '(none)'}")
    if not text.strip():
        raise UnreadableDocument(f"{path.name}: no text (a scanned document needs OCR first)")
    return text
