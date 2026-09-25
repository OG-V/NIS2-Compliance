# ADR 0006: Product adapters behind a neutral evidence model

**Status:** accepted

**Context:** The tool is meant to be run like a consultant engagement: the client grants
read access to its systems, and the tool checks them whatever products they run. The
first identity checks read Keycloak's own data (`bruteForceProtected`, `CONFIGURE_TOTP`),
so every new product would have meant new checks, and the legal mapping of each check
would have had to be repeated per product.

**Decision:** Each category of system gets a product-neutral evidence model that says
what the checks need to know (for identity: each user's second-factor state, whether new
users must enrol one, lockout, minimum password length, and sign-in paths that accept a
password alone). An adapter per product has two parts:

- `fetch` calls the product's API with the client's read-only credential and returns the
  raw answers unchanged;
- `normalize` is a pure function from those answers to the neutral model.

Checks read only the neutral model. Evidence files keep the raw answers next to the
normalised values, so each value can be traced to what the product returned. The product
is taken from the target file or detected (for identity providers, from the issuer in the
public OpenID configuration). The scan records which product each system runs and how
that was established. A recognised product without an adapter is reported by name as
unsupported, never guessed at.

Where a product's configuration can be read more or less strictly, the adapter takes the
reading that cannot overstate security (e.g. an Okta user without an active second
factor counts as without MFA, even if a policy will prompt them to enrol), and documents it.

**Consequences:** A check and its mapping to NIS2 and CIR 2024/2690 are written once. A new
product is a new adapter with its own tests, and normalisation is tested on recorded API
responses without the product being present. Each adapter embodies an interpretation of
its product's settings. These interpretations are documented in the adapter and tested,
and they need review like the requirement catalog does. Adapters are verified against a
live system where one is available (Keycloak on the lab, Okta on a developer org).
Otherwise they are marked as built from documentation only.
