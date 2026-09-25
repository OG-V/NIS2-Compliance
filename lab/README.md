# Demo target lab

A Docker Compose stack standing in for **NordMSP**, a fictional small managed service
provider. MSPs are one of the entity types CIR (EU) 2024/2690 applies to directly
(see [ADR 0002](../docs/adr/0002-extraction-source.md)).

```bash
./lab.sh up weak        # deliberately misconfigured
./lab.sh up hardened    # same stack, gaps closed
./lab.sh status
./lab.sh down           # removes containers and volumes
```

`up` always tears down the previous profile along with its volumes first, so only one
profile runs at a time. It also points the `.current` symlink at the active profile, and
[`target.yaml`](target.yaml) reads the org documents and admin password through it. The first start takes about a minute while Keycloak imports its realm.

> The weak profile is intentionally insecure. Every port binds to `127.0.0.1` only.
> The passwords in `profiles/*/lab.env` are lab-only values.

## Services and ports

| Service | Purpose | Host port |
|---|---|---|
| `web` | nginx customer portal (TLS) | 18080 (HTTP), 18443 (HTTPS) |
| `host` | Linux admin jump host (sshd) | 12222 |
| `idp` | Keycloak, realm `nordmsp` | 18081 |
| `logs` | Loki central log store | 13100 |
| `search` | Elasticsearch application log store (security on; scanner user `nis2scan`) | 19200 |
| `backup` | restic backup of `/data` (image built from `backup/`) | none (use `docker exec`) |
| `backup-borg` | BorgBackup backup of `/data` (image built from `backup-borg/`) | none (use `docker exec`) |
| `legacy-web` | forgotten, undocumented service (weak only) | none |
| `certgen` | one-shot: generates the web certificate | none |
| `search-setup` | one-shot, run by `lab.sh`: creates the `nis2scan` user and the log data | none |

The ports are chosen so the lab can run next to the Mini SOC lab, which uses 2222 and 8080.

## Answer key

These are the intended differences between the profiles. Milestone 3's checks should flag
every weak row and pass every hardened row. Each row below has been verified by probing
the running lab.

| NIS2 Art. 21(2) | What is observed | weak | hardened |
|---|---|---|---|
| (h) cryptography | TLS 1.0 handshake on 18443 | accepted | refused (alert 70) |
| (h) cryptography | Certificate validity | expired 2025-01-01 | valid 365 days |
| (h) cryptography | HTTP on 18080 | 200, plaintext | 301 → https, HSTS |
| (i) access control | SSH auth methods offered | `publickey,password` | `publickey` |
| (i) access control | `sshd -T` permitrootlogin / maxauthtries | yes / 10 | no / 3 |
| (j) MFA | Keycloak `CONFIGURE_TOTP` default action, users' required actions | off / none | on / all users |
| (i) access control | Keycloak brute-force protection, password policy | off / none | on / length ≥ 12 |
| (i) access control | Keycloak admin console `admin`/`admin` | works | 401 |
| (b) incident handling | Loki `limits_config.retention_period` | 7 days | 180 days |
| (b) incident handling | Elasticsearch retention of log data | index `app-logs-000001` under ILM policy `logs-7d` (Elasticsearch 8.19) | data stream `logs-nordmsp` with lifecycle retention 180 days (Elasticsearch 9.5) |
| (c) backups | Newest restic snapshot | 2025-06-01 (stale) | at start-up, then daily |
| (c) backups | Newest Borg archive; repository encryption | 2025-03-15 (stale); none | at start-up, then daily; repokey-blake2 |
| (i) asset management | Running services vs `org/assets.yaml` | `logs`, `search`, `backup`, `backup-borg`, `legacy-web` undeclared | all declared |
| (e) vulnerability handling | Fixable CRITICAL CVEs in running images (Trivy) | nginx 1.20 (Debian 11, end of support), Keycloak 26.3, Loki 3.5.1, Elasticsearch 8.19, restic 0.18.0 | current releases; restic rebuilt with OS updates; 3 Keycloak CVEs and 1 Elasticsearch CVE, all in bundled libraries, under time-limited risk exceptions |
| Art. 23 reporting | `org/incident-response.md` | no 24h/72h/1-month steps, no CSIRT, reviewed 2023 | complete, reviewed 2026-09-01 |

Each row is encoded as a test: `tests/test_checks.py` evaluates every check against
evidence recorded from both profiles (`tests/fixtures/evidence/`), and
`NIS2_LAB=1 pytest tests/test_lab_live.py` scans the running lab.

Notes:

- Loki's `/config` output has more than one `retention_period` key. Read
  `limits_config.retention_period`; don't grep for the key.
- The hardened IR plan's review date is fixed, so the "reviewed < 12 months" check will
  start failing in September 2027. That is correct behaviour, not a bug.
- The vulnerability row changes over time. New CVEs are published daily, and the Keycloak
  risk exceptions in `profiles/hardened/org/risk-exceptions.yaml` expire on 2026-10-31.
  A live scan of the hardened profile *should* start failing CHK-VUL-001 when that happens.
  The fix is to upgrade Keycloak or renew the exception on purpose; don't loosen the check.
- Keycloak MFA is enforced through the `CONFIGURE_TOTP` required action together with the
  built-in conditional-OTP browser flow. A stricter check could also inspect the
  authentication flow itself.
