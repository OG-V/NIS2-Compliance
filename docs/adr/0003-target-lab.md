# ADR 0003: Self-hosted Docker lab as scan target

**Status:** accepted

**Context:** Options were a cloud account (realistic, but it costs money, reviewers can't
reproduce it, and Prowler already covers it) or a self-hosted stack.

**Decision:** Use a Docker Compose lab with `weak` and `hardened` profiles.

**Consequences:** Anyone can reproduce it with one command, it costs nothing, and the
before/after demo is clear. It is less "enterprise" than a cloud account, and cloud
collectors can be added later behind the same collector interface.
