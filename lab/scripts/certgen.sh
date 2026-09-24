#!/bin/sh
# Generate the web server's self-signed certificate. CERT_MODE=expired makes
# one that expired on 2025-01-01, for the weak profile.
set -eu
case "$CERT_MODE" in
  valid)   validity="-days 365" ;;
  expired) validity="-not_before 20240101000000Z -not_after 20250101000000Z" ;;
  *) echo "unknown CERT_MODE: $CERT_MODE" >&2; exit 1 ;;
esac
# shellcheck disable=SC2086
openssl req -x509 -newkey rsa:2048 -nodes -sha256 \
  -keyout /certs/server.key -out /certs/server.crt \
  -subj "/O=NordMSP (lab)/CN=portal.nordmsp.lab" \
  -addext "subjectAltName=DNS:portal.nordmsp.lab,DNS:localhost" \
  $validity 2>/dev/null
openssl x509 -in /certs/server.crt -noout -subject -enddate
