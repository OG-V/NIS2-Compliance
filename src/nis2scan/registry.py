"""Registries of collectors and checks.

A collector gathers raw evidence from the target and returns it as a JSON-able
dict. A check is a pure function of that evidence, the organisational profile
and the current time, so it can be tested against recorded evidence without a
live target.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from nis2scan.config import Profile, Target
from nis2scan.models import CheckMeta, CheckStatus


class CollectorError(Exception):
    """Evidence could not be collected (service down, command failed, ...)."""


@dataclass(frozen=True)
class Result:
    status: CheckStatus
    message: str
    observed: dict[str, Any] = field(default_factory=dict)
    expected: dict[str, Any] = field(default_factory=dict)


def passed(message: str, observed: dict | None = None, expected: dict | None = None) -> Result:
    return Result(CheckStatus.PASS, message, observed or {}, expected or {})


def failed(message: str, observed: dict | None = None, expected: dict | None = None) -> Result:
    return Result(CheckStatus.FAIL, message, observed or {}, expected or {})


Evaluator = Callable[[dict[str, Any], Profile, datetime], Result]


@dataclass(frozen=True)
class Collector:
    name: str
    requires: str  # Target section that must be present, e.g. "web"
    collect: Callable[[Context], dict[str, Any]]


@dataclass(frozen=True)
class Check:
    meta: CheckMeta
    collector: str
    evaluate: Evaluator


COLLECTORS: dict[str, Collector] = {}
CHECKS: dict[str, Check] = {}


def collector(name: str, *, requires: str):
    def register(fn):
        if name in COLLECTORS:
            raise ValueError(f"duplicate collector {name}")
        COLLECTORS[name] = Collector(name, requires, fn)
        return fn

    return register


def check(*, collector: str, **meta):
    def register(fn: Evaluator) -> Evaluator:
        check_meta = CheckMeta(**meta)
        if check_meta.id in CHECKS:
            raise ValueError(f"duplicate check {check_meta.id}")
        CHECKS[check_meta.id] = Check(check_meta, collector, fn)
        return fn

    return register


def load_all() -> None:
    """Import every collector and check module so they register themselves."""
    for package in ("nis2scan.collectors", "nis2scan.checks"):
        pkg = importlib.import_module(package)
        for mod in pkgutil.iter_modules(pkg.__path__):
            importlib.import_module(f"{package}.{mod.name}")


class Context:
    """Runs collectors on demand and caches their evidence for the rest of the scan."""

    def __init__(self, target: Target):
        self.target = target
        self._cache: dict[str, dict[str, Any] | Exception] = {}

    def collect(self, name: str) -> dict[str, Any]:
        if name not in self._cache:
            try:
                evidence = self._run(name)
                evidence.setdefault("_collected_at", datetime.now(UTC).isoformat())
                self._cache[name] = evidence
            # A broken collector must not abort the scan; its checks report 'error'.
            except Exception as exc:  # noqa: BLE001
                self._cache[name] = exc
        cached = self._cache[name]
        if isinstance(cached, Exception):
            raise cached
        return cached

    def _run(self, name: str) -> dict[str, Any]:
        return COLLECTORS[name].collect(self)

    def evidence(self) -> dict[str, dict[str, Any] | Exception]:
        return dict(self._cache)
