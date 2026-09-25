"""Identity providers: the product-neutral evidence model, adapters and detection.

The checks in nis2scan.checks.identity read only IdentityEvidence. Each supported
product has an adapter that fetches the product's raw data (`fetch`, network) and
turns it into IdentityEvidence (`normalize`, a pure function, tested on recorded
API responses).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar

from pydantic import BaseModel

from nis2scan.config import IdpTarget


class IdentityUser(BaseModel):
    username: str
    enabled: bool
    mfa_enrolled: bool  # has at least one active second factor
    mfa_pending: bool = False  # will be made to enrol one at the next login


class IdentityEvidence(BaseModel):
    """What the identity checks need to know, whatever the product."""

    tenant: str  # realm, org or tenant name
    users: list[IdentityUser]
    new_users_must_enrol_mfa: bool
    lockout_enabled: bool  # accounts are locked after repeated failed logins
    lockout_max_attempts: int | None = None
    password_min_length: int  # 0 when no minimum is set
    password_policy: str  # the product's own description of the policy, for traceability
    # Sign-in paths (policies, apps) that accept a password alone. None when the product
    # has no sign-in policies separate from users' factors (then per-user MFA decides).
    password_only_sign_in: list[str] | None = None

    @property
    def users_without_mfa(self) -> list[str]:
        return [
            u.username for u in self.users if u.enabled and not u.mfa_enrolled and not u.mfa_pending
        ]


class DefaultLoginResult(BaseModel):
    username_tried: str
    accepted: bool
    detail: str = ""  # e.g. the HTTP status of the attempt


class IdentityAdapter:
    """One product. Subclasses set `product` and `label` and implement the methods."""

    product: ClassVar[str]  # identifier used in target files, e.g. "okta"
    label: ClassVar[str]  # display name, e.g. "Okta"
    # Target fields this product needs, e.g. ("api_token_env",). Checked before collecting.
    needs: ClassVar[tuple[str, ...]] = ()
    # Read-only access the client has to grant, for the onboarding checklist.
    access: ClassVar[str] = ""

    def fetch(self, idp: IdpTarget, secret) -> dict[str, Any]:
        """Call the product's API and return its raw answers, unchanged."""
        raise NotImplementedError

    def normalize(self, raw: dict[str, Any]) -> IdentityEvidence:
        raise NotImplementedError

    def check_access(self, idp: IdpTarget, secret) -> None:
        """Make one cheap read with the client's credential; raise CollectorError if refused."""
        raise NotImplementedError

    def try_default_login(self, idp: IdpTarget) -> DefaultLoginResult | None:
        """Try the product's documented default admin login once, or None if it has none."""
        return None


ADAPTERS: dict[str, IdentityAdapter] = {}


def adapter(cls: type[IdentityAdapter]) -> type[IdentityAdapter]:
    ADAPTERS[cls.product] = cls()
    return cls


@dataclass(frozen=True)
class Detection:
    product: str
    method: str  # "configured", or how it was recognised
    detail: str = ""


# Imported for their @adapter registrations.
from nis2scan.adapters.identity import entra, keycloak, okta  # noqa: F401
