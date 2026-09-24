# ADR 0005: Evaluate extraction with deterministic metrics, not an LLM judge

**Status:** accepted

**Context:** The extraction step needs a quality measure, both to decide whether its
output is worth reviewing and to answer "how do you know the LLM got it right?". A
common approach is to have a second LLM grade the output. That's fast, but the grader
has the same blind spots as the extractor, its scores drift between model versions,
and a disagreement can't be settled by reading the rule.

**Decision:** Score extractions against a hand-labelled gold set using only mechanical
rules:

| Metric | Rule |
|---|---|
| Quote validity | quote is a contiguous substring of the cited provision (whitespace and typographic quotes normalised) |
| Obligation recall | every keyword of a gold obligation appears in the obligation or quote of one accepted requirement |
| Granularity | accepted requirement count is inside the gold range |
| Testability accuracy | label is in the gold's accepted set |
| Invented specificity | numbers, durations, frequencies or crypto/standard names in the output that the provision never uses |

**Consequences:** Every score can be reproduced and challenged line by line, and the
metrics are cheap to re-run after a prompt change. The keyword rule is crude. It can't
tell a correct paraphrase from a wrong one, so it measures *coverage*, not *correctness*,
and correctness stays with the human reviewer. The gold set was drafted by Claude and
then verified by a human, since an LLM-labelled gold set for an LLM would be circular.
