"""Log stores: the product-neutral retention model, adapters and detection.

The retention check reads only LogRetentionEvidence. A log store can keep different
logs for different periods (Loki per stream selector, Elasticsearch per index or data
stream), so the model lists every scope with its own retention. The check judges
the shortest, because the shortest retention applies to some of the logs.
"""

from __future__ import annotations

import re
from datetime import timedelta
from typing import Any, ClassVar

from pydantic import BaseModel

from nis2scan.config import LogsTarget

DURATION_UNITS = {
    "nanos": timedelta(microseconds=0.001),
    "micros": timedelta(microseconds=1),
    "ms": timedelta(milliseconds=1),
    "s": timedelta(seconds=1),
    "m": timedelta(minutes=1),
    "h": timedelta(hours=1),
    "d": timedelta(days=1),
    "w": timedelta(weeks=1),
    "y": timedelta(days=365),
}


def parse_duration(text: str) -> timedelta:
    """Parse a duration such as Loki's '1w', '180d', '1d12h' or Elasticsearch's '7d'."""
    parts = re.findall(r"(\d+)(nanos|micros|ms|s|m|h|d|w|y)", text)
    if not parts or "".join(n + u for n, u in parts) != text:
        raise ValueError(f"not a duration: {text!r}")
    return sum((int(n) * DURATION_UNITS[u] for n, u in parts), timedelta())


def days(duration: str | None) -> int | None:
    """Whole days in a duration; None stays None (kept indefinitely)."""
    return parse_duration(duration).days if duration else None


class LogScope(BaseModel):
    name: str  # which logs, e.g. "all streams", "index logs-app-000001"
    retention_days: int | None  # None: never deleted
    source: str  # the setting that decides it, for traceability


class LogRetentionEvidence(BaseModel):
    store: str
    scopes: list[LogScope]

    @property
    def shortest(self) -> LogScope | None:
        """The scope whose logs are deleted first, or None if nothing is ever deleted."""
        finite = [s for s in self.scopes if s.retention_days is not None]
        return min(finite, key=lambda s: s.retention_days) if finite else None


class LogAdapter:
    """One log-store product. Subclasses implement the methods below."""

    product: ClassVar[str]
    label: ClassVar[str]
    needs: ClassVar[tuple[str, ...]] = ()
    access: ClassVar[str] = ""

    def recognise(self, logs: LogsTarget, secret) -> str | None:
        """A description of what identified the product, or None. Most products are
        recognised without credentials; cloud services only once signed in."""
        raise NotImplementedError

    def check_access(self, logs: LogsTarget, secret) -> None:
        raise NotImplementedError

    def fetch(self, logs: LogsTarget, secret) -> dict[str, Any]:
        raise NotImplementedError

    def normalize(self, raw: dict[str, Any]) -> LogRetentionEvidence:
        raise NotImplementedError


ADAPTERS: dict[str, LogAdapter] = {}


def adapter(cls: type[LogAdapter]) -> type[LogAdapter]:
    ADAPTERS[cls.product] = cls()
    return cls


# Imported for their @adapter registrations.
from nis2scan.adapters.logging import elasticsearch, loki, sentinel, splunk  # noqa: F401
