# ADR 0007: Human document review as evidence, verified and recorded by the tool

**Status:** accepted

**Context:** 64 of the catalog's 85 requirements have no automated check. Most are
organisational (policies, training, supplier management) or documentary (plans,
registers); some are technical but not yet automated. In a consultant engagement the
client provides the documents that evidence them. Reporting all of these as "not assessed"
understates what an engagement actually establishes. Letting a model judge the documents
would break ADR 0001: an adequacy judgement about a policy must be a person's, and
reproducible and accountable.

**Decision:** A named reviewer records each judgement in an evidence register: the
requirement, the documents reviewed, a verdict (evidenced, partially evidenced or not
satisfied), who reviewed, when, why, and optionally until when the review holds. The tool
does not judge documents. It verifies and records the decision:

- every referenced document must exist, and its SHA-256 is stored with the scan, so a
  document changed after its review is detectable;
- a review applies only to a catalog requirement that no automated check covers, so a
  document cannot overrule a failing check;
- the reviewer and a rationale are required; an evidenced verdict needs a document, while
  a "not satisfied" may rest on a document's absence;
- a review dated after the scan, past its validity, or whose document is missing makes
  the requirement "not assessed", never a pass; unknown, duplicate or check-covered
  entries are reported and not applied.

Every verdict records its basis (checks, document review, or none). The report shows
document-based evidence in its own colour and lists each review with its reasons and
document hashes. The AI narrative still explains only the failing checks.

**Consequences:** Most of an engagement's findings can now appear in one report, with the
difference between technical evidence and human judgement kept visible. The quality of a
document verdict is the reviewer's responsibility; the tool makes it traceable and
dated, not correct. A model could later suggest which requirements a document may cover,
for the reviewer to confirm, but the decision stays with the reviewer.
