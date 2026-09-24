# ADR 0001: No LLM in the verdict path

**Status:** accepted

**Context:** A compliance finding has to be reproducible and explainable to an auditor.
LLM output is nondeterministic and can't be audited line by line.

**Decision:** Pass/fail is decided only by deterministic, unit-tested Python checks. LLMs
are used offline for extraction (reviewed before use) and at report time for narration
(checked against findings). `nis2scan.checks` may not import any LLM client.

**Consequences:** Every verdict can be traced to check code, a finding, and a provision.
Each check has to be written by hand, which limits coverage. That limit is reported as
`not_assessed` rather than hidden.
