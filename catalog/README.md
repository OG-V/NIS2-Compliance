# Requirement catalog

| Path | Contents |
|---|---|
| `requirements/nis2-*.yaml` | Hand-authored requirements for NIS2 Art. 21(2) and Art. 23(4), reviewed |
| `requirements/cir-2024-2690/` | Requirements extracted from the CIR 2024/2690 Annex by `nis2scan extract` |
| `profile.yaml` | The organisation's own thresholds, each with a rationale |

## Review workflow for extracted requirements

1. `nis2scan extract --provision 11.7.1` (or `--gold`, or `--all`) writes one YAML file per
   requirement, with `review.status: draft`. A record whose quote isn't verbatim in the
   cited provision, or whose parameter value isn't in the text, is written as `rejected`
   with the reason in `review.notes`.
2. A human reads each draft against the provision text and edits it if needed. Then they
   set:

   ```yaml
   review:
     status: reviewed        # or: rejected
     reviewer: <name>
     reviewed_at: <date>
     notes: <what was checked or changed>
   ```

3. `nis2scan verify-quotes` and `nis2scan validate-catalog` must pass before committing.

Scans load only `reviewed` requirements. Re-running `extract` replaces drafts and
rejected records for a provision, but it never touches a provision that has reviewed
requirements.
