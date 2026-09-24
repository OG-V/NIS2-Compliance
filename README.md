# nis2scan — policy-as-code evidence scanner for NIS2

Checks a real system against technical requirements derived from the EU NIS2 Directive
(2022/2555) and Commission Implementing Regulation (EU) 2024/2690, with every verdict
traceable to a specific legal provision.

> **Status:** skeleton (milestone 1 of 6). See [docs/design.md](docs/design.md).

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
| `catalog/` | Reviewed requirement YAML and the organisational profile |
| `src/nis2scan/extract/` | Offline LLM extraction + quote verifier + evaluation |
| `src/nis2scan/collectors/` | Gather raw evidence from the target |
| `src/nis2scan/checks/` | Deterministic checks → findings |
| `src/nis2scan/report/` | Deterministic report + LLM narration |
| `lab/` | Demo target: Docker Compose stack for a fictional small MSP (`weak` / `hardened`) |

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest
nis2scan validate-catalog
```
