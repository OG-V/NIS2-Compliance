# Example reports

Real output from live scans of the demo lab on 2026-09-25. Nothing here is mocked.

| Folder | Lab profile | Result |
|---|---|---|
| [`weak/`](weak/) | deliberately misconfigured | 16/16 checks fail, 20 requirements not satisfied, AI narrative accepted on attempt 2 |
| [`hardened/`](hardened/) | gaps closed | 16/16 checks pass, 20 requirements partially evidenced, no gaps |

![Weak-profile report](weak-report.png)

Open `weak/report.html` in a browser to see the full report. GitHub displays HTML files as
source code. Each folder also holds the scan's raw material: `findings.json`,
`verdicts.json`, `scan.json` (tool version, profile hash, evidence hashes), `evidence/`, and
for the weak scan `narrative.json` (the accepted narrative and its model and prompt
version).

**Known weakness in the narrative:** because the validator only accepts numbers and terms
that occur in the scan data, the model tends to quote field names literally ("retention_days
7", "os_end_of_support") where a manager would need plain words. The next narrative prompt
version should ask for plain-language wording of the same facts.
