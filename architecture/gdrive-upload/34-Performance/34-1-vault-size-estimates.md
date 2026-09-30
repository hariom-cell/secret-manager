# 34.1 Vault Size Estimates

**Source:** §34 — Secret Manager Architecture Study

---

## 34. Performance Analysis

### 34.1 Vault Size Estimates

| Records | Estimated Size |
|---|---|
| 100 | ~50-200 KB |
| 1,000 | ~500 KB - 2 MB |
| 10,000 | ~5-20 MB |
| 100,000 | ~50-200 MB |

### 34.2 Unlock Time

| Operation | Desktop (128 MiB) | Mobile (64 MiB) |
|---|---|---|
| Argon2id | ~1.5-2.0s | ~0.8-1.2s |
| VEK decryption | <1 ms | <1 ms |
| DEK decryption (all) | 10-50 ms | 10-50 ms |
| Record loading | 5-20 ms | 5-20 ms |
| **Total** | **~2s** | **~1-2s** |

**With DUK (cached KEK):** No Argon2id needed. Single AES-GCM decryption. **Total: <100ms**.

### 34.3 Optimizations

1. Lazy decryption (decrypt on demand)
2. Record caching (keep recently accessed decrypted)
3. DEK prefetching for visible records
4. Background re-encryption after VEK rotation
5. Incremental sync (only changed records)

---
