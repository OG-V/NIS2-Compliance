# Changelog

## 0.2.0 (2026-09-26)

From a scanner for one demo lab to a tool a consultant can run on a client's estate.

**Desktop app**
- `nis2scan app`: a guided interface in six steps (authorisation, systems, documents and
  reviews, access check, scan, report), in its own window. On Windows with WSL, a desktop
  shortcut starts it without a terminal.
- Engagement folders hold the target, credentials (in a private secrets file), document
  reviews and every scan. The app runs the same code as the CLI.
- Documents are reviewed one at a time: the text on one side, the requirements to tick on
  the other. Reviews can be edited and deleted. Requirements with no document at all can
  be recorded as not satisfied in one step.
- Local only: bound to 127.0.0.1, with a one-time launch token.

**Evidence beyond checks**
- Document evidence ([ADR 0007](docs/adr/0007-document-evidence.md)): a named reviewer's
  decisions in an evidence register, with document hashes, validity dates and a written
  rationale. A review never overrules a check, and an expired review counts as not
  assessed.
- `nis2scan suggest`: an AI step that points to passages bearing on requirements no
  check covers. Every excerpt is verified against the document, and it never records a
  verdict. Measured against a reviewed gold set: recall 1.00, precision 0.91, and no
  suggestions for a decoy containing an injected instruction.

**More systems**
- Several assets per target section, each named in the report.
- Product adapters with detection ([ADR 0006](docs/adr/0006-product-adapters.md)):
  identity (Keycloak, Okta, Microsoft Entra ID), logs (Grafana Loki, Elasticsearch,
  Splunk, Microsoft Sentinel), backups (restic, BorgBackup, Veeam, AWS Backup, Azure
  Backup).
- A new check: every backup set is encrypted (CHK-BAK-002).
- Certificate pinning for self-signed servers.

**Engagements**
- The target records who authorised the scan and until when. Scans outside that window
  are refused, and active tests run only if allowed.
- `nis2scan onboard` lists the access each system needs, in the client's terms, and
  tests whether it is in place.

**Reports**
- Redesigned for non-technical readers, with a plain-language executive summary.
- `nis2scan diff` compares two scans: fixed, still open, new, and document review
  changes.
- Example reports regenerated from live scans of the lab.

## 0.1.0 (2026-09-25)

The first complete version: a requirement catalog from NIS2 and CIR 2024/2690 with
LLM-assisted extraction, quote verification and a gold-set evaluation; 16 deterministic
checks against a demo lab in weak and hardened profiles; and an HTML gap report with a
validated AI narrative.
