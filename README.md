# nis2scan — policy-as-code evidence scanner for NIS2

Checks a real system against technical requirements derived from the EU NIS2 Directive
(2022/2555) and Commission Implementing Regulation (EU) 2024/2690, with every verdict
traceable to a specific legal provision.

> **Status:** milestone 3 of 6: 16 deterministic checks running against the demo lab.
> LLM extraction (milestone 4) and the report (milestone 5) are next. See [docs/design.md](docs/design.md).

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
| `sources/` | Legal source texts, hashed (input to extraction) |
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
nis2scan scan --include-drafts     # --include-drafts: the catalog is not human-reviewed yet
nis2scan checks                    # every check and the requirement it maps to
```

A scan writes `out/<target>-<timestamp>/` containing `findings.json` (one per check),
`verdicts.json` (one per requirement), and `evidence/` (the raw evidence each finding
was judged on, with SHA-256 hashes recorded in `scan.json`).

| Profile | Checks | Requirement verdicts |
|---|---|---|
| `weak` | 16 fail | 7 `not_satisfied`, 4 `not_assessed` |
| `hardened` | 16 pass | 7 `partially_evidenced`, 4 `not_assessed` |

Even the hardened lab is only *partially evidenced*. Automated checks cover part of each
obligation, and the organisational measures (Art. 21(2)(a), (d), (f), (g)) need an audit.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest                                        # uses recorded evidence; no Docker needed
NIS2_LAB=1 pytest tests/test_lab_live.py      # scans the running lab
nis2scan validate-catalog
```
