# Design — v1

## 1. Problem framing (and what this tool does *not* claim)

NIS2 (Directive (EU) 2022/2555) is **outcome-based and technology-neutral**. Article 21(2)
lists ten risk-management measures (a)–(j) that must be "appropriate and proportionate";
it never says "SSH must use keys" or "keep logs 90 days". So a tool cannot honestly say
"this system is NIS2 compliant". What it *can* do:

> Collect technical evidence from a system, evaluate it with deterministic checks, and show
> — per legal provision — which obligations are evidenced, which have gaps, and which were
> never assessed.

Every output uses that vocabulary: `EVIDENCED` / `PARTIALLY_EVIDENCED` / `NOT_SATISFIED` /
`NOT_ASSESSED` — never "compliant".

## 2. Legal sources

| Source | Why |
|---|---|
| Directive (EU) 2022/2555 (NIS2), Art. 21(2), Art. 23 | The top-level obligations; the article every finding ultimately traces to. |
| Commission Implementing Regulation (EU) 2024/2690, Annex | Much more concrete technical requirements for Art. 21(2) (logging, backups, access control, MFA, crypto, patching…). **This is the realistic extraction target** — Art. 21 alone is too abstract to produce checkable rules. |
| ENISA technical implementation guidance for 2024/2690 | Human reference for interpreting requirements and choosing evidence. Not ingested in v1. |

CIR 2024/2690 applies directly only to certain digital-infrastructure / ICT-service entity
types — including **managed service providers (MSPs)**. The demo target is therefore framed
as a fictional small MSP, so the regulation genuinely applies to it.

Norway: NIS2 reaches Norway via the EEA Agreement; NIS1 is implemented through
*digitalsikkerhetsloven*. Verify the current incorporation status before citing it.

## 3. The three-layer traceability model

The core idea — and the main thing to defend in an interview — is that there are **three
different kinds of objects**, created by different means:

```
 Requirement  ── what the law says          (LLM-extracted, human-reviewed, versioned YAML)
     ▲  many-to-many, with coverage = full | partial
   Check      ── what our code tests        (hand-written Python, unit-tested)
     ▲  one-to-many
  Finding     ── what we observed           (produced at scan time, with raw evidence)
```

A check runs once per **asset**: each web endpoint, SSH host, identity provider, log
store, backup repository and Docker project the target lists, so one check yields one
finding per asset. The check itself stays a pure function of one asset's evidence. A
requirement is not satisfied if any of its checks fails on any asset, and the report
groups a failing check's assets into one gap ("fails on 2 of 40 web endpoints").

The step from *Requirement → Check* is an **interpretation**, made and documented by a
human (`coverage`, `severity_rationale`). The LLM never makes it silently.

Requirement verdict roll-up (deterministic, `nis2scan.models.rollup`):

| Findings for the requirement's checks | Requirement verdict |
|---|---|
| no checks mapped, or any check `ERROR` and none `FAIL` | `NOT_ASSESSED` |
| any `FAIL` | `NOT_SATISFIED` |
| all `PASS`, at least one check with `coverage: full` | `EVIDENCED` |
| all `PASS`, only partial coverage | `PARTIALLY_EVIDENCED` |

## 4. Where AI is (and is not) in the loop

```
            OFFLINE (build time)                               RUNTIME (scan)
 ┌───────────────────────────────────────┐   ┌──────────────────────────────────────────┐
 │ sources/*.txt ──LLM──► draft YAML     │   │ collectors ──► checks ──► findings.json  │
 │   │                    │              │   │   (no LLM)     (no LLM)      │           │
 │   │     deterministic quote verifier  │   │                              ▼           │
 │   │                    │              │   │               rollup ──► verdicts.json   │
 │   └─ human review ─────► catalog/     │──►│                              │           │
 │      (status: reviewed)               │   │                  LLM narration (report)  │
 └───────────────────────────────────────┘   │         + deterministic citation check   │
                                             └──────────────────────────────────────────┘
```

1. **Extraction (offline).** `nis2scan extract` sends one Annex provision per request to
   Claude Opus 5.5 (medium effort, chosen by measurement) and gets back schema-validated
   JSON (structured outputs, parsed into
   Pydantic models). Guard rails:
   - Every record must carry a verbatim `quote`; a **deterministic verifier** checks it
     appears in the *cited* provision of the hash-pinned source text. A parameter value
     the model claims is "stated in the text" must also appear there. Records that fail
     either check are stored as `rejected`, not dropped, so the failure rate is visible.
   - Re-running never overwrites a provision that already has reviewed requirements.
   - Only `review.status: reviewed` requirements are loaded by the scanner.
   - Extraction metadata (serving model, prompt version, source hash) is stored per
     record. Server-side refusal fallbacks are enabled, so the serving model is recorded
     rather than assumed.
   - **Evaluation** (`nis2scan evaluate`, [ADR 0005](adr/0005-deterministic-evaluation.md)):
     a gold set of 20 provisions / 55 obligations, scored with deterministic metrics:
     quote validity, obligation recall, granularity, testability accuracy and
     invented-specificity rate. No LLM grades the LLM.
2. **Verdicts (runtime): no LLM.** Checks are plain Python, each with known-good/known-bad
   fixture tests.
3. **Report (runtime).** `nis2scan report <run>` renders a self-contained HTML report
   and `report.json`. Every count, verdict, table and ordering comes from code. Gaps are
   organised **by failing check**, not by requirement: one technical problem usually
   breaches several provisions (the NIS2 article and the CIR points that detail it), and
   remediation belongs to the problem. Each gap lists every provision it breaches, with
   the verified quote and the hashed evidence file.

   The report is written for managers as well as engineers. It opens with a headline,
   one square per requirement coloured by verdict, and the gaps by severity, then lists
   the critical and high-severity gaps as actions. Each check carries a hand-written
   action and effort estimate, and a formatter per check restates its observed and
   expected values as "found" and "should be" lines. These fields are presentation
   only: they are kept out of the narrative's input, so the validator still checks the
   model against the scan data alone.

   `nis2scan diff <before> <after>` compares two scans check by check: fixed (fail to
   pass), still open, new (not failing before, failing now) and not comparable (errors,
   or checks in only one scan). It loads both runs the same way the gap report does, so
   the figures agree. It warns when the comparison may mislead: different targets, a
   reversed order, or a changed profile, catalog or tool version.
4. **Narrative (optional, `--narrate`).** The model receives only the gaps: finding,
   observed/expected values and legal text. It returns an executive summary plus one
   explanation per gap. A deterministic validator rejects the draft if it skips or
   invents a gap, cites a requirement the finding doesn't breach, uses a number or
   standard absent from *that gap's own* data, or claims (non-)compliance or
   certification. One retry gets the validator's objections. A draft that fails twice is
   not shown, and the report says why.
5. **Evidence suggestions (optional, `nis2scan suggest`).** For requirements no check
   covers, a model reads one client document (text, Word or PDF) and points to passages
   that bear on them. The list of unchecked requirements is sent as a cached block, so
   each further document costs little. Code rejects unknown or checked IDs, and each
   excerpt that is not verbatim in the document or is only a title or heading. A
   suggestion may quote several passages, and repeats of a requirement are merged. What
   remains is printed as
   commented-out register entries without a verdict, for the reviewer (ADR 0007).

## 5. Known hard parts (why "AI extracts rules from legal text" is messier than it sounds)

- **Invented specificity** is the #1 failure mode: models will "helpfully" produce
  "retain logs for 90 days" or "AES-256" where the law says "appropriate". Values the law
  leaves to the entity become `parameters` marked `entity_defined`, and our concrete
  thresholds live in an explicit, documented **organisational profile**
  (`catalog/profile.yaml`), not in the requirement.
- **Severity is not in the text.** The law doesn't rank obligations. Severity is assigned by
  a human on the *Check*, with a written rationale — not extracted.
- **Granularity is arbitrary and nondeterministic.** One sentence may become one rule or five,
  differently on each run, and current Claude models don't accept `temperature`, so
  sampling can't be pinned. Mitigations: fixed segmentation (one call per numbered point),
  stable IDs derived from provision numbers, a schema-constrained output, reviewed
  provisions being immune to re-extraction, and granularity measured against the gold set.
- **The source structure is irregular.** Sections 7 and 9 of the Annex have no
  subsections, so their `x.y` points are provisions rather than headings. The parser
  handles this, and a test checks that every numbered line is accounted for.
- **Cross-references and qualifiers** ("where appropriate", "in accordance with the
  classification of the asset", "taking into account the state of the art") carry legal
  meaning and get lost in paraphrase — hence the mandatory verbatim quote.
- **Grounding and readability pull in opposite directions.** The narrative validator only
  accepts numbers and technical terms found in each gap's own data. That blocks invented
  facts, but with Claude Opus 5 it nudged the model toward quoting field names
  ("retention_days 7"). Claude Opus 5.5 keeps the same facts in plain language (18 field
  names down to 1, [comparison](../eval/results/2026-09-25-opus-5-5.md)) under the same
  validator. The model changed; the validator was not loosened.
- **Most of Art. 21 is organisational** (policies, training, supply chain). No check can
  judge a policy, and no model may. A named reviewer judges these from the organisation's
  documents and records the decision in an evidence register; the tool hashes the
  documents, enforces who, when, why and until when, and never lets a review overrule a
  check ([ADR 0007](adr/0007-document-evidence.md)). Without a review they stay
  `NOT_ASSESSED`, and the report shows document-based evidence apart from check-based
  evidence: it states coverage and its basis, not just a pass rate.
- **Declared ≠ actual.** Reading `sshd_config` is not the same as proving password auth is
  refused. Where cheap, checks probe live behaviour (TLS handshake, SSH auth methods offered)
  rather than only parsing config.
- **Prior art:** Prowler and others ship NIS2 mappings for cloud accounts. The
  differentiator here is not "a scanner with a NIS2 label" but the evidenced
  requirement-level traceability and the evaluated extraction pipeline.

## 6. v1 scope (as built)

Target: `lab/`, a Docker Compose stack for a fictional small MSP in two profiles:
`weak` (realistic misconfigurations) and `hardened`. It is reproducible with one command,
so a reviewer can run the demo and watch the report change between profiles. The
profile differences are listed as an answer key in [lab/README.md](../lab/README.md).

| NIS2 Art. 21(2) | Lab component | Checks (17) |
|---|---|---|
| (h) cryptography | nginx | TLS versions below the profile minimum refused (live handshake); certificate valid; HTTP redirects to HTTPS with HSTS |
| (i) access control | sshd host | password authentication not offered (live probe); root login disabled; auth attempts limited (`sshd -T`) |
| (i), (j) identity | Keycloak (also Okta, Entra ID) | MFA enrolled or enforced for all staff, and no sign-in by password alone; lockout after failed logins; password length; default admin credentials rejected |
| (b) incident handling | Loki, Elasticsearch | log retention at least the profile minimum, judged on the shortest-kept logs |
| (c) backups | restic, BorgBackup | a recent snapshot in every backup set; every set encrypted |
| (i) asset management | Docker, `assets.yaml` | every running service is inventoried |
| (e) vulnerabilities | Trivy on running images | no fixable CRITICAL CVE unless covered by an unexpired risk exception ([ADR 0004](adr/0004-risk-exceptions.md)) |
| Art. 23(4), (b) | `incident-response.md` | IR plan names the 24h / 72h / one-month reporting stages and the CSIRT; reviewed within 12 months |

Each check maps to its NIS2 article, and where the CIR point has been extracted and
reviewed, to that point as well ([check mapping](check-mapping.md)).

**Beyond the lab.** A target file lists any number of assets per section, so the
network-based checks (TLS, certificate, HTTPS redirect, offered SSH login methods) work on
any reachable host. A collector declares the asset fields it needs, e.g. `sshd -T`
needs a container. An asset without them skips those checks as not applicable rather
than failing them.

**Engagements.** A scan is run for a client who grants access. The target's
`engagement` section records who authorised the scan, the window it is valid for, and
whether active tests may run. Collectors that interact beyond reading (so far the
one-time default admin login) are marked active and are skipped otherwise. Scans outside
the window are refused, and the engagement is shown in the report. `nis2scan onboard`
lists, per system, the access the client must grant in the client's terms (e.g. "an Okta
API token created by a Read-only Administrator"). With probing it checks each item:
ports, Docker containers, product detection, a single read-only request with each
credential, and documents on disk. It can write the list as a Markdown checklist to send.

**Self-signed servers.** Splunk and Veeam usually present self-signed certificates, and
Splunk's default certificate is issued by a CA shared by every installation, so trusting
that CA would trust any Splunk server. A target can instead pin the server's certificate
by its SHA-256 fingerprint, checked on the connection that carries the requests, or name a
certificate file to trust. Certificate checks cannot be switched off. When onboarding meets
an untrusted certificate, it shows the fingerprint to confirm with the client.

**Products.** Identity providers are read through product adapters behind a neutral
evidence model ([ADR 0006](adr/0006-product-adapters.md)): Keycloak (verified on the lab),
Okta (verified on a live developer org) and Microsoft Entra ID (verified on a live free
tenant with security defaults; Conditional Access is tested on documented responses).
Accounts that sign in at another provider, such as guests or the personal Microsoft
account that created a tenant, are marked external: their MFA happens where the tested
product cannot see it, so they are listed rather than counted as lacking MFA. The product is detected from the
provider's OpenID configuration, or set with `product:` in the target, and the report
lists every system with its product and how it was identified. Log stores follow the same
pattern: Grafana Loki and Elasticsearch, both verified on the lab, which runs one of each;
Splunk, verified on a local Splunk Enterprise 10.4 container with the built-in `user` role
(its own `history`, `summary` and `_*` indexes are not the organisation's logs and are left
out); and Microsoft Sentinel, verified on a live workspace (workspace default and per-table
retention, long-term retention counted as kept).
Each adapter lists every retention scope (Loki's global period and per-stream overrides;
Elasticsearch's indices under ILM policies and data streams under their own lifecycle
or ILM), and the check judges the shortest. Backups too: restic and BorgBackup, both
verified on the lab, and Veeam Backup & Replication, built from its REST API reference
and tested on documented responses (it needs a Windows server and a licence, so it is not
yet verified live). restic and Borg run either inside the client's backup container,
already configured with its repository, or on the scanning host with the repository and
a password from the secrets (passed in the environment, never on the command line). Veeam
is read through its REST API with a Backup Viewer account, trusting the server's own
certificate when it is self-signed; there is no option to skip certificate checks.
Cloud backups are read the same way: AWS Backup through the AWS CLI (verified on a live
account with a DynamoDB backup) and Azure Backup through Azure Resource Manager with an
Entra app registration holding Backup Reader (sign-in, permission and vault listing
verified on a live subscription; protected items tested on documented responses only).
A repository or server holds backup sets (restic: per host and paths; Veeam: per backup
job; cloud: per protected resource). Every set must have a recent backup and be
encrypted; the worst set decides.

**Desktop app.** `nis2scan app` is a guided interface for consultants, in six steps:
authorisation, systems, documents and reviews, access check, scan, report. It is a local
web page in a browser's app mode (its own window, no address bar), served by a small
standard-library HTTP server, so it adds no dependencies. It is a front end, not a
second implementation: the access check calls onboarding per system, the scan calls
`run_scan` with a context that reports each collector as it runs, and the report is the
same rendered HTML. Everything for one client lives in an engagement folder:
`target.yaml`, `secrets.env` (readable only by its owner, never shown again), document
suggestions and `results/`. Forms are validated with the target model the scanner uses,
and reviews go through the same `Review` validation and are appended to the register
without rewriting it, so the reviewer's comments survive. The server binds to 127.0.0.1
and requires a same-site cookie set from a one-time launch token, and checks the `Host`
header and a JSON content type, so another website in the consultant's browser cannot
drive the scanner (a cross-site form or DNS rebinding) or read results. On Windows with WSL,
a desktop shortcut starts the app inside WSL, where the scanner's tools run, and opens an
Edge app window on the Windows side. The app stops when the window has been closed and
no task is running.

**Planned but not built:** checks that logs are actually shipped centrally and that
authentication events are logged. The lab's Loki instance receives no logs, so only
retention is checked.

**Out of scope for v1:** a hosted, multi-user web service (the desktop app runs locally
for one consultant; v1 ships it alongside the CLI and the static HTML report), cloud accounts, the Q&A/RAG
stretch goal, and any claim about national transposition law.

## 7. Tech stack

- Python 3.12+, Pydantic v2 (schemas), Typer + Rich (CLI), PyYAML, pytest; CI runs lint,
  catalog integrity and tests on Python 3.12, 3.13 and 3.14
- Collectors: the Docker CLI (`docker exec`, `docker inspect`), Python `ssl` and
  `cryptography` for TLS and certificates, `paramiko` for the SSH auth-method probe, the
  Keycloak admin REST API, Loki's `/config` endpoint, Trivy (pinned by digest)
- LLM layer (extraction + narration): Anthropic Python SDK, `claude-opus-5-5` at medium
  effort, chosen by measurement ([comparison](../eval/results/2026-09-25-opus-5-5.md)) and
  configurable with `--model`/`--effort`; structured outputs; an optional `llm` extra, so
  the scanner runs without an API key
- Report: Jinja2, rendering a self-contained static HTML file plus JSON
- Desktop app: the standard library's HTTP server and plain HTML, CSS and JavaScript (no
  build step, no network access), shown in a browser's app mode

## 8. Milestones

1. **Schema + catalog** — models, validator, hand-written requirements. *(done)*
2. **Lab** — compose stack with `weak`/`hardened` profiles. *(done)*
3. **Checks** — 12 collectors, 16 checks with recorded-evidence tests; `nis2scan scan` → JSON. *(done)*
4. **Extraction** — ingest 2024/2690 Annex, LLM extraction, quote verifier, gold-set eval. *(done; results in [eval/results](../eval/results/))*
5. **Report** — deterministic HTML report, then LLM narration with citation verification. *(done)*
6. *(stretch, not built)* Q&A over scan results.
