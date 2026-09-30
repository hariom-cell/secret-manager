# section-33

**Source:** §33 — Secret Manager Architecture Study

---

## 33. Database Corruption & Recovery

| Scenario | Impact | Recovery |
|---|---|---|
| Power loss during write | Possible corruption | SQLite WAL recovery |
| Single record corrupted | One record unreadable | Others unaffected |
| Vault metadata corrupted | Cannot unlock | Restore from backup |
| Entire DB lost | Complete data loss | Restore from backup |

**On vault open:**
1. Read vault_metadata
2. Attempt KEK derivation and VEK decryption
3. For each record: attempt DEK and payload decryption
4. Corrupted records flagged, not silently accepted
5. Present successfully decrypted records + list of corrupted ones
6. NEVER delete the vault file (allow recovery attempts)

---
