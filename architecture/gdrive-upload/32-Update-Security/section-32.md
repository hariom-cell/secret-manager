# section-32

**Source:** §32 — Secret Manager Architecture Study

---

## 32. Update Security

```
Update Process:
1. Check for update (user-initiated or periodic)
2. Download over HTTPS
3. Verify Ed25519 signature against embedded public key
4. Verify package hash
5. Verify version ≥ minimum supported
6. Install via platform mechanism
7. Verify new installation signature
```

**Anti-rollback:** Minimum version enforced on unlock. Vault format version only increases.

---
