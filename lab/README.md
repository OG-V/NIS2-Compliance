# Demo target lab (milestone 2)

A Docker Compose stack standing in for a fictional small managed service provider, the
kind of entity CIR (EU) 2024/2690 applies to directly.

Planned services: Linux host with sshd, nginx TLS reverse proxy, Keycloak (IdP), Postgres,
restic backups, a log collector, plus `docs/incident-response.md` for documentary checks.

Two profiles:

- `weak`: realistic misconfigurations (password SSH, TLS 1.0 allowed, no MFA, stale backups)
- `hardened`: the same stack with the gaps closed

The demo scans both and diffs the gap reports.
