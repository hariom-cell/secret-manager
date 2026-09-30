# section-28

**Source:** §28 — Secret Manager Architecture Study

---

## 28. Account Model

| Option | Description | Security | Sync |
|---|---|---|---|
| A: No account | Fully local | Best | None |
| B: Local account | Device-local | Good | None |
| C: Optional cloud | Email for sync coordination | Medium | Yes |
| D: Zero-knowledge | Email for identity, E2E data | Best | Yes |
| E: Device-based | Device ID + pubkey as identity | Good | P2P possible |

**Recommended: Hybrid A + D.** No account required for core use. Optional zero-knowledge account for sync. Email is used for identity coordination only — vault data remains E2E encrypted.

---
