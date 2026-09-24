"""Live probes of the web endpoint: TLS versions, certificate, HTTP behaviour."""

import http.client
import socket
import ssl
import warnings

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from nis2scan.registry import Context, collector

TLS_VERSIONS = {
    "TLSv1": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def _client_context(version: ssl.TLSVersion | None = None) -> ssl.SSLContext:
    # We want to learn what the *server* accepts, so the client accepts anything:
    # no certificate verification and every cipher, including legacy ones.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    if version:
        with warnings.catch_warnings():  # pinning to TLS 1.0/1.1 is deprecated in Python
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx.minimum_version = ctx.maximum_version = version
    return ctx


def _accepts(host: str, port: int, version: ssl.TLSVersion) -> bool:
    with socket.create_connection((host, port), timeout=5) as sock:
        try:
            with _client_context(version).wrap_socket(sock):
                return True
        except ssl.SSLError:
            return False


@collector("tls_probe", requires="web")
def tls_probe(ctx: Context) -> dict:
    web = ctx.target.web
    accepted = {name: _accepts(web.host, web.https_port, v) for name, v in TLS_VERSIONS.items()}

    with (
        socket.create_connection((web.host, web.https_port), timeout=5) as sock,
        _client_context().wrap_socket(sock) as tls,
    ):
        der = tls.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    return {
        "endpoint": f"{web.host}:{web.https_port}",
        "protocols_accepted": accepted,
        "certificate": {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        },
    }


@collector("http_probe", requires="web")
def http_probe(ctx: Context) -> dict:
    web = ctx.target.web
    plain = http.client.HTTPConnection(web.host, web.http_port, timeout=5)
    plain.request("GET", "/")
    r = plain.getresponse()
    http_result = {"status": r.status, "location": r.getheader("Location")}
    plain.close()

    secure = http.client.HTTPSConnection(
        web.host, web.https_port, timeout=5, context=_client_context()
    )
    secure.request("GET", "/")
    r = secure.getresponse()
    https_result = {
        "status": r.status,
        "strict_transport_security": r.getheader("Strict-Transport-Security"),
        "server": r.getheader("Server"),
    }
    secure.close()
    return {"http": http_result, "https": https_result}
