"""Log stores: which product it is, and how long it keeps logs.

The product is detected (or taken from the target), then its adapter fetches the raw
retention settings and normalises them. Evidence keeps both.
"""

from nis2scan.adapters.logging import ADAPTERS
from nis2scan.config import LogsTarget
from nis2scan.registry import CollectorError, Context, collector


def detect(logs: LogsTarget) -> dict:
    if logs.product != "auto":
        if logs.product not in ADAPTERS:
            raise CollectorError(
                f"unknown log store {logs.product!r}; supported: {', '.join(sorted(ADAPTERS))}"
            )
        return {"product": logs.product, "method": "configured", "detail": ""}
    for adapter in ADAPTERS.values():
        if how := adapter.recognise(logs):
            return {"product": adapter.product, "method": how, "detail": ""}
    raise CollectorError(
        f"could not recognise the log store at {logs.url}; set `product:` in the target "
        f"(supported: {', '.join(sorted(ADAPTERS))})"
    )


@collector("logs_detect", requires="logs")
def logs_detect(ctx: Context, logs: LogsTarget) -> dict:
    found = detect(logs)
    return {**found, "label": ADAPTERS[found["product"]].label}


@collector("log_retention", requires="logs")
def log_retention(ctx: Context, logs: LogsTarget) -> dict:
    adapter = ADAPTERS[ctx.collect("logs_detect", logs)["product"]]
    raw = adapter.fetch(logs, ctx.target.secret)
    return {
        "product": adapter.product,
        "retention": adapter.normalize(raw).model_dump(),
        "raw": raw,
    }
