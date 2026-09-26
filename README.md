# nis2scan: policy-as-code evidence scanner for NIS2

[![CI](https://github.com/OG-V/NIS2-Compliance/actions/workflows/ci.yml/badge.svg)](https://github.com/OG-V/NIS2-Compliance/actions/workflows/ci.yml)

nis2scan checks a real system against the EU's NIS2 cybersecurity rules. It covers
Directive (EU) 2022/2555 and the technical requirements of Commission Implementing
Regulation (EU) 2024/2690, and every verdict traces back to a specific legal provision.
It links a legal reading of the regulation to a working technical implementation:
legal text becomes structured requirements, deterministic checks gather evidence against
them, and the result is a gap report that non-engineers can read.

![Gap report for the deliberately weak lab](docs/example-report/weak-report.png)

*Part of a real report on the demo lab. See the [example reports](docs/example-report/).*

## What it does

1. **Turns legal text into checkable requirements.** An LLM drafts structured
   requirements from the regulation. Code verifies every quote against the official text,
   and a human reviews each one before it is used.
2. **Collects evidence and judges it deterministically.** 17 checks probe a live system:
   TLS handshakes, SSH authentication methods, identity-provider settings, log retention,
   backups, container CVEs and incident-response documents. No model is involved in any
   pass/fail verdict.
3. **Reports gaps in plain language.** The HTML report opens with the result at a glance
   and the problems to fix first, then maps the findings onto the NIS2 security measures.
   Each gap says what was found, what it should be and what to do, and keeps the breached
   provisions, the verified legal text and the hashed evidence one click away. An
   optional AI narrative is shown only if a validator confirms it against the findings.
4. **Runs like an engagement.** `nis2scan onboard` tells the client exactly what access
   each system needs and tests that it works, and can write it as a checklist. The target
   records who authorised the scan and until when. Scans outside that window are refused,
   and active tests (such as trying a default admin password) run only if allowed.
5. **Records human judgement where no check can reach.** Most of NIS2 is organisational:
   policies, training, suppliers, plans. A named reviewer judges those from the
   organisation's documents and records the decision in an evidence register. The tool
   hashes the documents, requires a reviewer, date and rationale, and never lets a review
   overrule a check or outlive its validity ([ADR 0007](docs/adr/0007-document-evidence.md)).
   `nis2scan evidence-template` starts the register from the catalog, and
   `nis2scan suggest` drafts entries for a document, with no verdict, for the reviewer.
6. **Shows progress between scans.** `nis2scan diff` compares two scans of the same target:
   what was fixed, what is still open and what is new
   ([example](docs/example-report/#example-reports)).

The tool never says a system is "NIS2 compliant". NIS2 is outcome-based, and much of it
is organisational. Requirements are reported as `partially_evidenced`, `not_satisfied`
or `not_assessed`, and the report says how much it could and could not assess.

## Results

| | |
|---|---|
| **Demo lab** | The `weak` profile fails 17 of 17 checks, and document review fails 4 more requirements (25 not satisfied). The `hardened` profile passes 17 of 17 checks and 9 document reviews (30 requirements evidenced, 21 of them by checks). Both are reproducible with one command. |
| **Extraction quality** (gold set: 20 provisions, 55 obligations) | Quotes verbatim: 100%. Obligations found: 100%. Invented numbers or durations: 0. Open values mislabelled as stated: 0%. |
| **Run-to-run stability** | Two runs agree on 19/20 provision structures, clause overlap 0.99. |
| **Narrative grounding** | Every citation, every number and full gap coverage are checked by code, and IDs are kept out of the prose. A draft that fails twice is not shown. |
| **Catalog** | 85 requirements (11 from NIS2, 74 from CIR 2024/2690), all reviewed, with every quote verified against EUR-Lex. |
| **Tests** | 394 tests, run in CI on Python 3.12 to 3.14 without Docker or an API key. |

Each figure has a write-up in [`eval/results/`](eval/results/), including what went
wrong and what was changed: three extraction prompt versions, a narrative prompt revision
and a model comparison.

## How the AI is kept in check

| Step | What the LLM does | What constrains it |
|---|---|---|
| Extraction (offline) | Drafts requirements from one Annex provision at a time | A schema-validated output. Quotes are checked verbatim against the cited provision. A "stated" value must appear in the text. A human reviews every record. Reviewed work is never re-extracted. |
| Verdicts (runtime) | Nothing | [ADR 0001](docs/adr/0001-no-llm-in-verdict-path.md). A test fails if the checks package imports an LLM client. |
| Narrative (runtime) | Explains each failing check and suggests remediation | It sees only the gap data. A deterministic validator checks coverage, citations, per-gap grounding of numbers and standards, and bans compliance claims ([ADR 0005](docs/adr/0005-deterministic-evaluation.md)). |
| Evidence suggestions (optional) | Points to passages in a client document that bear on requirements no check covers | Only unchecked catalog IDs are accepted, and each excerpt must appear verbatim in the document. The output is a commented-out register entry with no verdict, which the register refuses until a named reviewer completes it. Scored against a gold set. |
| Evaluation | Nothing | The gold set and metrics are mechanical rules. No LLM grades an LLM. |

```
legal text ─LLM─► draft requirements ─verify + human review─► catalog ─┐
                                                                        ▼
target system ──► collectors ──► checks ──► findings ──► verdicts ──LLM─► gap report
                                 (no LLM)                (no LLM)       (validated)
```

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'

lab/lab.sh up weak                      # demo target in Docker; or: hardened
nis2scan onboard                        # access each system needs, and whether it works
nis2scan scan                           # evidence, findings and verdicts under out/
nis2scan report out/<run>               # self-contained HTML gap report
nis2scan diff out/<before> out/<after>  # progress between two scans
```

The AI features are optional and need an Anthropic API key (`pip install -e '.[llm]'`):

```bash
nis2scan report out/<run> --narrate     # add the validated AI narrative
nis2scan extract --provision 11.7.1        # draft requirements from an Annex point
nis2scan evaluate eval/runs/<run>          # score extractions against the gold set
nis2scan suggest org/evidence/*.md --base org   # draft register entries for documents
```

Drafted requirements go to `catalog/requirements/cir-2024-2690/`, and scans ignore them
until a human reviews them ([review workflow](catalog/README.md)).

## Repository guide

| Path | Contents |
|---|---|
| [`docs/design.md`](docs/design.md) | Design, the traceability model, known hard parts, scope as built |
| [`docs/adr/`](docs/adr/) | Decision records: no LLM in verdicts, extraction source, lab target, risk exceptions, deterministic evaluation, product adapters, document evidence |
| [`docs/check-mapping.md`](docs/check-mapping.md) | Which check evidences which legal requirement (generated, kept in sync by a test) |
| [`lab/`](lab/) | Demo target: a fictional managed service provider in `weak` and `hardened` profiles, with an answer key |
| [`sources/`](sources/) | NIS2 and CIR 2024/2690 texts from EUR-Lex, hash-pinned |
| [`catalog/`](catalog/) | Reviewed requirements and the organisation's own thresholds (`profile.yaml`) |
| [`eval/`](eval/) | Gold set, extraction runs and their results |
| `src/nis2scan/` | `collectors/` and `checks/` (deterministic), `extract/` (LLM, offline), `report/` (HTML + narrative) |

## Limitations

- **Evidence, not compliance.** Most of NIS2 is organisational. 64 of 85 requirements have
  no automated check. They are not assessed unless a named reviewer records a document
  review, and a review is a person's judgement, recorded and verified by the tool, not
  made by it.
- **Demo target.** The lab is a small Docker stack, not a production estate. A target can
  list many web endpoints and hosts, and the network-based checks work on any of them.
  Identity providers (Keycloak, Okta, Microsoft Entra ID), log stores (Loki,
  Elasticsearch, Splunk, Microsoft Sentinel) and backups (restic, BorgBackup, Veeam, AWS
  Backup, Azure Backup) are detected and read through adapters. Veeam, and Azure's protected items, are tested on
  documented API responses only.
  Cloud accounts are out of scope.
- **Interpretation is human, and published.** The requirement catalog, the gold-set labels
  and the [check-to-requirement mapping](docs/check-mapping.md) were drafted with Claude
  and reviewed by the author. All three are in the repository so they can be challenged.
- **The recall metric measures coverage, not correctness.** Whether a paraphrase is
  faithful is left to the human reviewer.
- **Time-dependent results.** New CVEs appear daily, and the hardened lab's Keycloak risk
  exception expires on 2026-10-31. After that date its vulnerability check is expected to
  fail until Keycloak is upgraded or the exception is deliberately renewed.

## Development

```bash
pip install -e '.[dev,llm]'
pytest                                      # recorded lab evidence and a fake LLM client
NIS2_LAB=1 pytest tests/test_lab_live.py    # scans the running lab
nis2scan validate-catalog && nis2scan verify-quotes
nis2scan checks --markdown > docs/check-mapping.md   # after changing a check's mapping
```

## License

The code is released under the [MIT License](LICENSE). The legal texts in `sources/` are
© European Union and reused under EUR-Lex's terms (see [sources/README.md](sources/README.md)).
