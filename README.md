# nis2scan — policy-as-code evidence scanner for NIS2

Checks a real system against technical requirements derived from the EU NIS2 Directive
(2022/2555) and Commission Implementing Regulation (EU) 2024/2690, with every verdict
traceable to a specific legal provision.

> **Status:** milestone 4 of 6: the scanner (16 deterministic checks) and the LLM extraction
> pipeline are done. The first extraction run covered the 20 gold-set provisions:
> 74 requirements, every quote verbatim, and no invented values
> ([results](eval/results/2026-09-25-gold.md)), all reviewed and approved. Prompt v2 cut
> vague stated values from 37% to 5–7%, and two repeat runs agree on 18/20 provisions
> ([stability](eval/results/2026-09-25-prompt-v2.md)). Prompt v3 made the one nested-list
> provision stable across runs ([v3](eval/results/2026-09-25-prompt-v3.md)).
> The HTML gap report with a validated AI narrative (milestone 5) is done. See [docs/design.md](docs/design.md).

## Design in one paragraph

An LLM runs **offline** to turn legal text into draft, structured requirements. Each one
carries a verbatim quote that is verified by code, and a human reviews it before it is used.
The scan itself is **plain deterministic Python**: no model is involved in a pass/fail
verdict. An LLM then turns the scan output into a readable gap report, and code checks
every claim in that report against the findings it cites.

```
legal text ─LLM─► draft requirements ─verify+review─► catalog/ ─┐
                                                                  ▼
target system ──► collectors ──► checks ──► findings ──► verdicts ──LLM─► gap report
                                 (no LLM)                (no LLM)       (citation-checked)
```

The tool reports requirements as `evidenced`, `partially_evidenced`, `not_satisfied` or
`not_assessed`. It never claims a system is "NIS2 compliant". NIS2 is outcome-based, and
most of it is organisational, so automated evidence can't settle compliance.

## Layout

| Path | Contents |
|---|---|
| `docs/` | Design doc and architecture decision records |
| `eval/` | Gold set for evaluating extraction |
| `sources/` | Legal texts from EUR-Lex as normalised plain text, with hashes |
| `catalog/` | Requirement YAML and `profile.yaml` (the organisation's thresholds) |
| `src/nis2scan/extract/` | Offline LLM extraction + quote verifier + evaluation |
| `src/nis2scan/collectors/` | Gather raw evidence from the target |
| `src/nis2scan/checks/` | Deterministic checks → findings |
| `src/nis2scan/report/` | Deterministic report + LLM narration |
| `lab/` | Demo target: Docker Compose stack for a fictional small MSP (`weak` / `hardened`). See [lab/README.md](lab/README.md) |

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'

lab/lab.sh up weak                 # or: hardened
nis2scan scan
nis2scan checks                    # every check and the requirement it maps to
nis2scan report out/<run>          # HTML gap report; add --narrate for an AI-drafted,
                                   # mechanically validated narrative (needs an API key)
```

A scan writes `out/<target>-<timestamp>/` containing `findings.json` (one per check),
`verdicts.json` (one per requirement), and `evidence/` (the raw evidence each finding
was judged on, with SHA-256 hashes recorded in `scan.json`).

| Profile | Checks | Requirement verdicts (85 reviewed requirements) |
|---|---|---|
| `weak` | 16 fail | 20 `not_satisfied`, 65 `not_assessed` |
| `hardened` | 16 pass | 20 `partially_evidenced`, 65 `not_assessed` |

Even the hardened lab is only *partially evidenced*. Automated checks cover part of each
obligation. Most requirements are *not assessed*: the organisational measures
(Art. 21(2)(a), (d), (f), (g)) need an audit, and many CIR points have no check yet.
The report states this coverage rather than hiding it.

## Extracting requirements with an LLM

Requires an Anthropic API key, and costs API credits (one request per provision):

```bash
pip install -e '.[llm]'
export ANTHROPIC_API_KEY=...

nis2scan extract --gold                    # the 20 gold-set provisions
nis2scan evaluate                          # score them (deterministic, no LLM)
nis2scan extract --provision 11.7.1        # or a single provision; --all for all 159
```

Drafts go to `catalog/requirements/cir-2024-2690/`. Scans ignore them until a human
reviews them ([catalog/README.md](catalog/README.md)). `nis2scan verify-quotes` checks
every quote in the catalog against the stored legal text.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest                                        # uses recorded evidence; no Docker needed
NIS2_LAB=1 pytest tests/test_lab_live.py      # scans the running lab
nis2scan validate-catalog
```
