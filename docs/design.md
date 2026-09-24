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

1. **Extraction (offline).** LLM turns provisions into draft `Requirement` records with
   structured output. Guard rails:
   - Every record must carry a verbatim `quote`; a **deterministic verifier** checks it is
     a substring of the hashed source text. Records that fail are rejected.
   - Only `review.status: reviewed` requirements are loaded by the scanner.
   - Extraction metadata (model, prompt version, source hash) is stored per record.
   - **Evaluation:** a hand-labelled gold set (~25 provisions) measures extraction
     precision/recall and "invented specificity" rate. This is what makes the AI use
     defensible rather than decorative.
2. **Verdicts (runtime): no LLM.** Checks are plain Python, each with known-good/known-bad
   fixture tests.
3. **Report narration (runtime).** The LLM receives *only* `verdicts.json`, findings, and the
   requirement quotes, and returns structured sections that cite finding IDs. A
   deterministic post-check rejects output that cites unknown IDs or describes a status
   that contradicts the verdict. All numbers/tables in the report are rendered by code,
   not the LLM.

## 5. Known hard parts (why "AI extracts rules from legal text" is messier than it sounds)

- **Invented specificity** is the #1 failure mode: models will "helpfully" produce
  "retain logs for 90 days" or "AES-256" where the law says "appropriate". Values the law
  leaves to the entity become `parameters` marked `entity_defined`, and our concrete
  thresholds live in an explicit, documented **organisational profile**
  (`catalog/profile.yaml`), not in the requirement.
- **Severity is not in the text.** The law doesn't rank obligations. Severity is assigned by
  a human on the *Check*, with a written rationale — not extracted.
- **Granularity is arbitrary and nondeterministic.** One sentence may become one rule or five,
  differently on each run. Mitigations: fixed segmentation (one call per numbered point),
  temperature 0, stable IDs derived from provision numbers, and diffing re-extractions
  against the reviewed catalog instead of overwriting it.
- **Cross-references and qualifiers** ("where appropriate", "in accordance with the
  classification of the asset", "taking into account the state of the art") carry legal
  meaning and get lost in paraphrase — hence the mandatory verbatim quote.
- **Most of Art. 21 is organisational** (policies, training, supply chain). These get
  `testability: organisational` and are reported as `NOT_ASSESSED`. Showing that honestly
  is a feature: the report states coverage, not just pass rate.
- **Declared ≠ actual.** Reading `sshd_config` is not the same as proving password auth is
  refused. Where cheap, checks probe live behaviour (TLS handshake, SSH auth methods offered)
  rather than only parsing config.
- **Prior art:** Prowler and others ship NIS2 mappings for cloud accounts. The
  differentiator here is not "a scanner with a NIS2 label" but the evidenced
  requirement-level traceability and the evaluated extraction pipeline.

## 6. v1 scope

Target: `lab/` — a Docker Compose stack for a fictional small MSP, in two profiles:
`weak` (realistic misconfigurations) and `hardened`. Reproducible with one command, so a
reviewer can run the demo and see the gap report change between profiles.

| NIS2 Art. 21(2) | Lab component | Candidate checks (≈12–15 total) |
|---|---|---|
| (j) MFA | Keycloak (IdP) | OTP required for admin realm; brute-force detection on |
| (i) access control / asset mgmt | Linux host (sshd), inventory file | SSH password auth disabled; root login disabled; running containers ⊆ declared asset inventory |
| (h) cryptography | nginx reverse proxy | TLS < 1.2 refused (live handshake); HTTP redirects to HTTPS; cert not expired |
| (b) incident handling / logging | Loki or rsyslog | central log shipping configured; retention ≥ profile value; auth events logged |
| (c) backups | restic | newest snapshot < profile max age |
| (e) vulnerability handling | Trivy on lab images | no CRITICAL vulns with fix available, unless covered by an unexpired risk exception ([ADR 0004](adr/0004-risk-exceptions.md)) |
| Art. 23 reporting (documentary) | `lab/docs/incident-response.md` | IR plan exists, contains 24h/72h/1-month reporting steps and CSIRT contact, reviewed < 12 months |

Explicitly **out of v1**: web dashboard (the Mini SOC already demonstrates FastAPI/React;
v1 ships a CLI + static HTML report), cloud accounts, the Q&A/RAG stretch, and any claim
about national transposition law.

## 7. Tech stack

- Python 3.12+, Pydantic v2 (schemas), Typer (CLI), PyYAML, pytest
- Collectors: `docker` SDK, `paramiko`/`ssh -G`-style probing, `ssl`/`sslyze`, Keycloak admin
  REST API, Trivy JSON output
- LLM layer (extraction + narration): Anthropic SDK behind a small interface, structured
  outputs; optional dependency so the scanner runs without an API key
- Report: Jinja2 → static HTML + JSON (findings, verdicts)

## 8. Milestones

1. **Schema + catalog** — models, validator, hand-written requirements. *(done)*
2. **Lab** — compose stack with `weak`/`hardened` profiles. *(done)*
3. **Checks** — 12 collectors, 16 checks with recorded-evidence tests; `nis2scan scan` → JSON. *(done)*
4. **Extraction** — ingest 2024/2690 Annex, LLM extraction, quote verifier, gold-set eval.
5. **Report** — deterministic HTML report, then LLM narration with citation verification.
6. *(stretch)* Q&A over scan results.
