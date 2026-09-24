# ADR 0004: Time-limited risk exceptions for unfixable vulnerabilities

**Status:** accepted

**Context:** When CHK-VUL-001 was first run, even the newest Keycloak image (26.7.4) had
fixable CRITICAL CVEs in bundled Java libraries (netty, BouncyCastle). Fixed versions
exist upstream, but the vendor hasn't shipped a release containing them, and the operator
can't patch a vendor image. There were three options: fail forever, loosen the check, or
record a management decision.

**Decision:** The target can provide a risk-exception register
(`documents.risk_exceptions`). An exception matches one vulnerability in one image
repository, and it has an owner, an approver, a reason, compensating measures, and an
expiry date. The check does not fail on vulnerabilities covered by an unexpired exception,
but it lists them as `accepted_risks` in the finding. Expired exceptions are reported and
stop suppressing anything.

**Consequences:** This matches how risk acceptance works in practice (NIS2 Art. 21(1)
requires measures to be proportionate to the risk). The finding never hides that
something was accepted. The expiry date makes acceptance a recurring decision, not a
permanent loophole. Exceptions are organisational evidence, so their quality (is the
reason good?) is out of scope for automated checking.
