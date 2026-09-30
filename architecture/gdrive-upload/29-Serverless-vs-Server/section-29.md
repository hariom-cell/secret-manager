# section-29

**Source:** §29 — Secret Manager Architecture Study

---

## 29. Serverless vs Server-Based

| Dimension | Serverless | Local + ZK Server |
|---|---|---|
| Security | Best | Excellent |
| Privacy | Perfect | Perfect (E2E) |
| Complexity | Low | Medium |
| Cost | None | Server hosting |
| Sync | Manual (file transfer) | Automatic (E2E encrypted) |

**Recommendation:** Start serverless, add optional zero-knowledge sync server later.

---
