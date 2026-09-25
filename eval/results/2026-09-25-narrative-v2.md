# Narrative prompt 2026-09-25.2: a summary managers can read (2026-09-25)

**Question:** can the executive summary drop the check IDs from its text and lead with
the most severe problems, without losing grounding?

**Why:** the redesigned report is aimed at non-technical readers. The accepted summary from
prompt `2026-09-25.1` was accurate but listed sixteen check IDs inline ("… (CHK-AST-001,
CHK-DOC-001, CHK-IDP-002, …)"). The report now has its own fix-first list and a card for
every gap, so the summary no longer needs to list them all.

**Change:**

- Prompt: never write finding or requirement IDs in the text. Citations go only in the
  structured fields (`executive_summary_finding_ids`, `requirement_ids`), which the report
  now shows as links to the gap cards. Start with the overall result, then describe the
  most severe gaps. The summary need not mention every gap.
- Validator: a new rule rejects any `CHK-` or `REQ-` ID in the narrative text, so the
  instruction is enforced mechanically.

**Setup:** the live weak-lab scan from `docs/example-report/weak`, narrated twice with
Claude Opus 5.5 at `medium` effort. Only the prompt changed. The baseline is the accepted
narrative already in the example report.

## Results

| | Baseline (`.1`) | Run A (`.2`) | Run B (`.2`) |
|---|---|---|---|
| Validator | accepted, attempt 2 | accepted, attempt 2 | accepted, attempt 2 |
| Passes the new ID rule | no | yes | yes |
| IDs in the text | 16 | 0 | 0 |
| Executive summary (words) | 98 | 92 | 99 |
| Gaps the summary cites | 16 (all) | 7 (critical and high) | 8 (critical, high, one medium) |
| Whole narrative (words) | 1,267 | 1,186 | 1,163 |
| Data field names used as words | 3 | 3 | 1 |

Word counts are whitespace-separated tokens. Field names are `snake_case` or `camelCase`
words in the text, such as `bruteForceProtected`.

Both new summaries follow the same structure: the overall result (16 of 16 checks failed,
20 requirements not satisfied, 65 not assessed), then the default admin login, then the
other high-severity gaps, each with a short consequence:

> **Baseline:** "High-severity gaps follow: the newest backup is 480 days old (CHK-BAK-001),
> two staff accounts lack MFA (CHK-IDP-001), SSH offers password login and allows direct
> root login (CHK-SSH-001, CHK-SSH-002), …"
>
> **Run B:** "The newest backup is 480 days old, leaving data recovery at serious risk. Two
> staff accounts, including an administrator, have no multi-factor authentication."

The per-gap explanations were already free of IDs, and they stay so.

## What this does not show

- **Why attempt 1 failed.** All three narratives were accepted on the second attempt, but
  the first attempt's violations are not recorded, so it is unknown whether the new ID
  rule caused any of the retries. Recording rejected attempts would answer this.
- **Grounding of consequences.** Phrases such as "anyone who knows it can take control" are
  interpretation, not data. The validator checks numbers, standards, citations and
  compliance language. Whether an explanation is fair is left to the reader, as before.

## Decision

Prompt `2026-09-25.2` is the default. Run B is the narrative in the example report,
chosen for its fewer raw field names. Both runs are kept here:
[`2026-09-25-narrative-v2-a.json`](2026-09-25-narrative-v2-a.json) and
[`2026-09-25-narrative-v2-b.json`](2026-09-25-narrative-v2-b.json).
