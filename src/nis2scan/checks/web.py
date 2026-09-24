"""Cryptography on the web endpoint (NIS2 Art. 21(2)(h))."""

from datetime import datetime

from nis2scan.config import Profile
from nis2scan.registry import check, failed, passed

VERSION_ORDER = ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
CRYPTO = ["REQ-NIS2-21.2.H"]


@check(
    id="CHK-TLS-001",
    title="TLS versions below the profile minimum are refused",
    requirements=CRYPTO,
    coverage="partial",
    severity="high",
    severity_rationale="Legacy TLS allows downgrade attacks on traffic to a public service.",
    target_type="https_endpoint",
    collector="tls_probe",
)
def legacy_tls_refused(ev: dict, profile: Profile, now: datetime):
    minimum = profile.tls.min_version
    accepted = [v for v in VERSION_ORDER if ev["protocols_accepted"].get(v)]
    too_old = [v for v in accepted if VERSION_ORDER.index(v) < VERSION_ORDER.index(minimum)]
    observed = {"accepted_versions": accepted}
    expected = {"min_version": minimum}
    if too_old:
        return failed(f"Server accepts {', '.join(too_old)}", observed, expected)
    return passed(f"Server only accepts {', '.join(accepted)}", observed, expected)


@check(
    id="CHK-TLS-002",
    title="Certificate is valid and not about to expire",
    requirements=CRYPTO,
    coverage="partial",
    severity="medium",
    severity_rationale=(
        "An invalid certificate trains users to click through warnings, "
        "which makes interception easier."
    ),
    target_type="https_endpoint",
    collector="tls_probe",
)
def certificate_valid(ev: dict, profile: Profile, now: datetime):
    cert = ev["certificate"]
    not_before = datetime.fromisoformat(cert["not_before"])
    not_after = datetime.fromisoformat(cert["not_after"])
    days_left = (not_after - now).days
    observed = {
        "not_before": cert["not_before"],
        "not_after": cert["not_after"],
        "days_left": days_left,
    }
    expected = {"min_days_remaining": profile.tls.cert_min_days_remaining}
    if now < not_before:
        return failed("Certificate is not yet valid", observed, expected)
    if now >= not_after:
        return failed(f"Certificate expired on {not_after.date()}", observed, expected)
    if days_left < profile.tls.cert_min_days_remaining:
        return failed(f"Certificate expires in {days_left} days", observed, expected)
    return passed(f"Certificate valid for {days_left} more days", observed, expected)


@check(
    id="CHK-TLS-003",
    title="Plain HTTP redirects to HTTPS and HSTS is set",
    requirements=CRYPTO,
    coverage="partial",
    severity="medium",
    severity_rationale="Without a redirect and HSTS, users can be kept on unencrypted HTTP.",
    target_type="https_endpoint",
    collector="http_probe",
)
def https_enforced(ev: dict, profile: Profile, now: datetime):
    http, https = ev["http"], ev["https"]
    redirects = http["status"] in (301, 302, 307, 308) and (http["location"] or "").startswith(
        "https://"
    )
    hsts = bool(https["strict_transport_security"])
    observed = {
        "http_status": http["status"],
        "location": http["location"],
        "hsts": https["strict_transport_security"],
    }
    expected = {"http_redirects_to_https": True, "hsts": True}
    problems = [
        msg
        for ok, msg in [
            (redirects, "HTTP does not redirect to HTTPS"),
            (hsts, "no Strict-Transport-Security header"),
        ]
        if not ok
    ]
    if problems:
        return failed("; ".join(problems), observed, expected)
    return passed("HTTP redirects to HTTPS and HSTS is set", observed, expected)
