# 38.1 Vault File Format

**Source:** §38 — Secret Manager Architecture Study

---

## 38. Package Formats

### 38.1 Vault File Format

```
┌─────────────────────────────────────────────────────────────────────┐
│  VAULT FILE FORMAT (version 1)                                      │
├─────────────────────────────────────────────────────────────────────┤
│ Offset  │ Size    │ Field                    │ Description        │
├─────────────────────────────────────────────────────────────────────┤
│ 0-3     │ 4 B     │ magic                    │ 0x564C5451 ("VLTQ")│
│ 4-5     │ 2 B     │ version                  │ Vault format ver   │
│ 6       │ 1 B      │ flags                   │ Bitfield           │
│ 7       │ 1 B      │ kdf_algorithm_id        │ 0x01 = Argon2id    │
│ 8-23    │ 16 B    │ vault_salt               │ Argon2id salt      │
│ 24-39   │ 16 B    │ kek_wrap_nonce           │ Nonce for VEK wrap │
│ 40-71   │ 32 B    │ wrapped_vek              │ VEK encrypted      │
│ 72-87   │ 16 B    │ vek_tag                  │ Auth tag           │
│ 88-103  │ 16 B    │ kek_cache_nonce          │ Nonce for KEK cache│
│ 104-151 │ 48 B    │ kek_cache_blob           │ Cached KEK wrap    │
│ 152-167 │ 16 B    │ kek_cache_tag            │ Cache auth tag     │
│ 168-183 │ 16 B    │ vault_crc                │ CRC of header      │
├─────────────────────────────────────────────────────────────────────┤
│ 184+    │ variable│ vault_payload            │ Encrypted blob:    │
│         │         │                          │ record_directory + │
│         │         │                          │ record ciphertexts │
└─────────────────────────────────────────────────────────────────────┘
Total header: 184 bytes (fixed)
```

### 38.2 Record Wire Format (inside vault_payload)

```
┌─────────────────────────────────────────────────────────────────────┐
│  RECORD WIRE FORMAT                                                 │
├─────────────────────────────────────────────────────────────────────┤
│ Offset  │ Size    │ Field                    │ Description        │
├─────────────────────────────────────────────────────────────────────┤
│ 0-3     │ 4 B     │ record_magic             │ 0x52454344 ("RECD")│
│ 4-5     │ 2 B     │ record_type_id           │ Type enum          │
│ 6-7     │ 2 B     │ flags                    │ Bitfield           │
│ 8-15    │ 8 B     │ record_id                │ UUID (first 8 B)  │
│ 16-23   │ 8 B     │ created_at               │ Encrypted timestamp│
│ 24-31   │ 8 B     │ modified_at              │ Encrypted timestamp│
│ 32-35   │ 4 B     │ dek_wrap_nonce           │ Nonce for DEK wrap │
│ 36-67   │ 32 B    │ wrapped_dek              │ DEK encrypted      │
│ 68-83   │ 16 B    │ dek_tag                  │ Auth tag           │
│ 84-107  │ 24 B    │ payload_nonce            │ XChaCha20 nonce    │
│ 108+    │ variable│ payload_ciphertext       │ Encrypted record   │
│ ...+16   │ 16 B    │ payload_tag              │ Poly1305 tag       │
└─────────────────────────────────────────────────────────────────────┘
Per-record overhead: 108 bytes (header) + 16 bytes (tag) = 124 bytes
```

### 38.3 Design Principles

1. **Magic bytes** for format identification and corruption detection.
2. **Version fields** for forward/backward compatibility.
3. **Algorithm ID fields** for cryptographic agility.
4. **Fixed-size headers** for easy parsing.
5. **Per-record self-contained** (nonce + ciphertext + tag).
6. **AAD binding** to prevent record type confusion.

---
