# Narrative on a multi-asset scan (2026-09-26)

**Question:** does narrative prompt `2026-09-25.2` still work now that the scan has
changed underneath it?

**What changed since the last measurement** ([prompt v2](2026-09-25-narrative-v2.md)):

- 17 checks instead of 16 (CHK-BAK-002, backup encryption).
- The lab has two log stores (Loki, Elasticsearch) and two backup tools (restic, Borg), so
  three gaps span several assets. The model sees each failing asset's own values
  (`failing_assets`), and the validator grounds every number in that gap's data.
- Identity evidence uses the product-neutral model (`lockout_enabled`,
  `new_users_must_enrol_mfa`, …) instead of Keycloak's field names.

The prompt, model (Claude Opus 5.5) and effort (`medium`) are unchanged.

**Setup:** a fresh live scan of the weak lab, narrated once. It is the narrative in
`docs/example-report/weak`, also kept here as
[`2026-09-26-narrative-multi-asset.json`](2026-09-26-narrative-multi-asset.json).

## Results

| | Prompt v2, run B (16 checks) | This run (17 checks, multi-asset) |
|---|---|---|
| Validator | accepted, attempt 2 | accepted, attempt 2 |
| IDs in the text | 0 | 0 |
| Executive summary (words) | 99 | 87 |
| Gaps the summary cites | 8 | 7 (the critical and high ones) |
| Whole narrative (words) | 1,163 | 1,336 |
| Data field names used as words | 1 | 1 (`retention_period`) |

The multi-asset gaps are explained per asset, with each asset's own values:

> "Both elasticsearch (ILM policy logs-7d) and loki (retention_period 1w) delete logs after
> 7 days, while the profile expects at least 90 days."
>
> "the newest borg backup is 559 days old and the newest restic backup is 481 days old"

The encryption gap names only the Borg repository, which is the one that fails, and the
steps are specific to it ("Create an encrypted borg repository and move backups into it").
The longer narrative is one more gap, and the multi-asset gaps take more words.

## What this does not show

As before, the first attempt's violations are not recorded, so the reason for the retry is
unknown.

## Decision

No change: prompt `2026-09-25.2` stays the default. The narrative is used in the example
report.
