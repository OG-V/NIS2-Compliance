# NordMSP — Backup and Recovery Plan

Version 2.0 · Owner: Head of Operations · Last reviewed: 2026-08-20

| Service | Backup | Recovery point (max data loss) | Recovery time |
|---|---|---|---|
| Customer portal | nightly, restic | 24 hours | 4 hours |
| Identity provider | nightly, restic and Borg | 24 hours | 2 hours |
| Log store | continuous, replicated | 1 hour | 8 hours |

Backups are encrypted and kept off the production network. Restores are tested quarterly;
the last restore test was 2026-07-02 (customer portal, completed in 2 h 40 min).
