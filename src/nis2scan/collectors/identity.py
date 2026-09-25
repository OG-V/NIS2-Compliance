"""Identity providers: which product it is, its configuration, and its default login.

The product is detected (or taken from the target), then its adapter fetches the raw
configuration and normalises it. Evidence keeps both, so every normalised value can
be traced back to what the product's API returned.
"""

from nis2scan.adapters.identity import ADAPTERS
from nis2scan.adapters.identity.detect import detect
from nis2scan.config import IdpTarget
from nis2scan.registry import CollectorError, Context, NotApplicable, collector


@collector("idp_detect", requires="idp")
def idp_detect(ctx: Context, idp: IdpTarget) -> dict:
    d = detect(idp)
    return {
        "product": d.product,
        "label": ADAPTERS[d.product].label,
        "method": d.method,
        "detail": d.detail,
    }


def _adapter(ctx: Context, idp: IdpTarget):
    adapter = ADAPTERS[ctx.collect("idp_detect", idp)["product"]]
    missing = [f for f in adapter.needs if not getattr(idp, f)]
    if missing:
        raise CollectorError(f"{adapter.label} needs {', '.join(missing)} set in the target")
    return adapter


@collector("idp_config", requires="idp")
def idp_config(ctx: Context, idp: IdpTarget) -> dict:
    adapter = _adapter(ctx, idp)
    raw = adapter.fetch(idp, ctx.target.secret)
    return {
        "product": adapter.product,
        "identity": adapter.normalize(raw).model_dump(),
        "raw": raw,
    }


@collector("idp_default_admin", requires="idp", active=True)
def idp_default_admin(ctx: Context, idp: IdpTarget) -> dict:
    adapter = ADAPTERS[ctx.collect("idp_detect", idp)["product"]]
    result = adapter.try_default_login(idp)
    if result is None:
        raise NotApplicable(f"{adapter.label} has no default admin login")
    return {"product": adapter.product, **result.model_dump()}
