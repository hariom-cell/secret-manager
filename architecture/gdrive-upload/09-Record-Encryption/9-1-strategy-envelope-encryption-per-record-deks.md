# 9.1 Strategy: Envelope Encryption (Per-Record DEKs)

**Source:** §9 — Secret Manager Architecture Study

---

## 9. Record Encryption

### 9.1 Strategy: Envelope Encryption (Per-Record DEKs)

```
Vault Layer:
┌─────────────────────────────────────────────────────────────┐
│  Vault Payload (encrypted with VEK)                         │
│                                                             │
│  For each record:                                           │
│  ┌───────────────────────────────────────────────────────┐  │
│  │ DEK (32 bytes) encrypted under VEK                    │  │
│  │ Payload (nonce + ciphertext + tag) encrypted under DEK│  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**DEK wrapping (VEK → DEK):**
```
wrapped_dek = AES-256-GCM_Encrypt(
    key = VEK,
    nonce = counter_based_nonce(record_index),
    plaintext = DEK,
    AAD = "DEK_WRAP" || record_type || version
)
```

**Record encryption (DEK → payload):**
```
ciphertext = XChaCha20-Poly1305_Encrypt(
    key = DEK,
    nonce = CSPRNG(24 bytes),
    plaintext = record_plaintext,
    AAD = "RECORD" || record_type || record_id
)
```

### 9.2 Why Envelope Encryption?

1. **Key rotation granularity.** VEK changes only require DEK wrapper re-encryption, not record plaintext re-encryption.
2. **Record-level deletion.** When a record is deleted, its DEK can be zeroized — no ciphertext traces remain.
3. **Blast radius limiting.** Compromise of one DEK does not affect other records.
4. **Forward secrecy for sharing.** Only the specific DEK needs to be wrapped under a sharing key.

Overhead: 48 bytes per record (12-byte nonce + 32-byte DEK + 16-byte tag). For 10,000 records: ~480 KB. Negligible.

### 9.3 What Gets Encrypted

| Data | Encrypted? | Notes |
|---|---|---|
| Record content | **Yes** | Encrypted with DEK |
| Record name/title | **Yes** | Part of record plaintext |
| Usernames | **Yes** | Part of record plaintext |
| URLs | **Yes** | Part of record plaintext |
| Secure notes body | **Yes** | Encrypted with DEK |
| TOTP secret | **Yes** | Encrypted with DEK |
| Credit card number | **Yes** | Encrypted with DEK |
| Cardholder name | **Yes** | Encrypted with DEK |
| SSH private key | **Yes** | Encrypted with DEK |
| Recovery codes | **Yes** | Encrypted with DEK |
| Attachments | **Yes** | Encrypted with DEK |
| Creation timestamp | **Encrypted** | Prevents usage pattern leakage |
| Modification timestamp | **Encrypted** | Same concern |
| Record type | **Plaintext** | Needed for UI display. Limited info leak. |
| Record ID | **Plaintext** | Random UUID. Limited info leak. |
| Wrapped DEK blob | **Plaintext** | Encrypted under VEK. Fixed size. |
| Folder names | **Encrypted** | Part of record/metadata plaintext |
| Tags | **Encrypted** | Part of record plaintext |

### 9.4 Metadata Leakage

| Data Point | Leakage | Severity | Mitigation |
|---|---|---|---|
| Record count | Record count in directory | Low-Medium | Acceptable — no practical mitigation |
| Record types | Plaintext in directory | Low | Coarse categories, acceptable |
| Record sizes | Encrypted size | Low | Optional padding |
| Timestamps | Encrypted | — | Encrypted per §9.3 |
| Attachment sizes | Encrypted size | Low | Encrypt separately, pad |
| Vault version | Public | Negligible | Public information |

**Padding:** Do NOT implement uniform padding by default. The usability cost (4 KB minimum for a 6-character PIN) is not worth the marginal privacy improvement. Offer padding as an optional high-privacy mode for power users.

### 9.5 Search Index

**Recommendation: Decrypted in-memory index.**
- When vault is unlocked, all records are decrypted in memory.
- Build search index from plaintext in memory.
- On vault lock, zeroize the index.
- No plaintext is ever written to disk.
- This is the approach used by Bitwarden and 1Password.

---
