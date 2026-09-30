# 11.1 Threat Assessment

**Source:** §11 — Secret Manager Architecture Study

---

## 11. Metadata Privacy

### 11.1 Threat Assessment

| Data Point | Leakage | Attack Value | Mitigation |
|---|---|---|---|
| Number of records | Record count | Determines if target is high-value | Minimal — accept |
| Record types | Plaintext in directory |  targeting | Low risk |
| Record sizes | Encrypted size | Infers secret types | Low risk |
| Timestamps | Now encrypted | Activity patterns | Encrypted |
| Folder structure | Part of record data | Organizational structure | Encrypted |
| Record names | Now encrypted |  | Encrypted |

### 11.2 Recommended Protections

1. **Encrypt timestamps.** Store creation/modification times encrypted under the DEK.
2. **Encrypt record names and folder names.** These are part of the record plaintext.
3. **Accept record type leakage.** Needed for UI icon/format display. Coarse categories limit information value.
4. **Accept record count leakage.** Hiding requires dummy records — significant complexity for marginal benefit.

---
