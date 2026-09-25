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
- **Most of Art. 21 is organisational** (policies, training, supply chain). These get
  `testability: organisational` and are reported as `NOT_ASSESSED`. Showing that honestly
  is a feature: the report states coverage, not just pass rate.
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

| NIS2 Art. 21(2) | Lab component | Checks (16) |
|---|---|---|
| (h) cryptography | nginx | TLS versions below the profile minimum refused (live handshake); certificate valid; HTTP redirects to HTTPS with HSTS |
| (i) access control | sshd host | password authentication not offered (live probe); root login disabled; auth attempts limited (`sshd -T`) |
| (i), (j) identity | Keycloak | MFA enrolled or enforced for all staff; brute-force protection; password length; default admin credentials rejected |
| (b) incident handling | Loki | log retention at least the profile minimum |
| (c) backups | restic | recent snapshot exists |
| (i) asset management | Docker, `assets.yaml` | every running service is inventoried |
| (e) vulnerabilities | Trivy on running images | no fixable CRITICAL CVE unless covered by an unexpired risk exception ([ADR 0004](adr/0004-risk-exceptions.md)) |
| Art. 23(4), (b) | `incident-response.md` | IR plan names the 24h / 72h / one-month reporting stages and the CSIRT; reviewed within 12 months |

Each check maps to its NIS2 article, and where the CIR point has been extracted and
reviewed, to that point as well ([check mapping](check-mapping.md)).

**Beyond the lab.** A target file lists any number of assets per section, so the
network-based checks (TLS, certificate, HTTPS redirect, offered SSH login methods) work on
any reachable host. A collector declares the asset fields it needs, e.g. `sshd -T`
needs a container. An asset without them skips those checks as not applicable rather
than failing them. The identity, logging and backup collectors still speak one product
each (Keycloak, Loki, restic); supporting others means a normalised evidence model per
area with one adapter per product.

**Planned but not built:** checks that logs are actually shipped centrally and that
authentication events are logged. The lab's Loki instance receives no logs, so only
retention is checked.

**Out of scope for v1:** a web dashboard (the Mini SOC project already demonstrates
FastAPI/React; v1 ships a CLI and a static HTML report), cloud accounts, the Q&A/RAG
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

## 8. Milestones

1. **Schema + catalog** — models, validator, hand-written requirements. *(done)*
2. **Lab** — compose stack with `weak`/`hardened` profiles. *(done)*
3. **Checks** — 12 collectors, 16 checks with recorded-evidence tests; `nis2scan scan` → JSON. *(done)*
4. **Extraction** — ingest 2024/2690 Annex, LLM extraction, quote verifier, gold-set eval. *(done; results in [eval/results](../eval/results/))*
5. **Report** — deterministic HTML report, then LLM narration with citation verification. *(done)*
6. *(stretch, not built)* Q&A over scan results.
