# 10.1 Architecture Decision: Application-Level Envelope Encryption + SQLite

**Source:** §10 — Secret Manager Architecture Study

---

## 10. Encrypted Local Database

### 10.1 Architecture Decision: Application-Level Envelope Encryption + SQLite

We do NOT use SQLCipher. Here's why:

| Aspect | SQLCipher | Application-Level Envelope |
|---|---|---|
| Encryption scope | Entire DB under one key | Per-record DEKs + VEK |
| Key management | Single key | Hierarchical (KEK → VEK → DEKs) |
| Granularity | All-or-nothing | Per-record key rotation, deletion |
| Blast radius | Single key = full vault | Single DEK = one record |
| Corruption handling | Whole-DB corruption | Per-record corruption isolated |
| Migration | Must re-encrypt entire DB | Incremental re-encryption possible |

**Decision:** Application-level envelope encryption over raw SQLite. The SQLite database stores:
1. **Encrypted vault payload** — a BLOB containing all encrypted records.
2. **Plaintext vault metadata** — version, algorithm IDs, Argon2id parameters, wrapped VEK.
3. **Plaintext record directory** — lightweight index of record IDs, types, sizes, nonces.

**On-disk structure:**

```
Table: vault_metadata
├── id: INTEGER PRIMARY KEY (1)
├── version: INTEGER
├── kdf_algorithm: TEXT ("argon2id")
├── kdf_params: BLOB (serialized Argon2id parameters)
├── salt: BLOB (16 bytes)
├── kek_wrap_nonce: BLOB
├── wrapped_vek: BLOB (VEK encrypted under KEK)
├── vek_tag: BLOB (authentication tag)
└── vault_created/modified: INTEGER (optional timestamps)

Table: record_directory
├── record_id: TEXT PRIMARY KEY (UUID v4)
├── record_type: TEXT ("login", "note", "card", etc.)
├── record_size: INTEGER (encrypted size)
├── payload_offset: INTEGER (byte offset in vault_blob)
├── payload_length: INTEGER (length in vault_blob)
├── dek_nonce: BLOB (nonce for DEK wrapping)
├── wrapped_dek: BLOB (DEK encrypted under VEK)
├── dek_tag: BLOB (authentication tag)
├── created/modified: INTEGER (encrypted timestamps)
└── aad: BLOB (associated authenticated data)

Table: vault_blob
├── id: INTEGER PRIMARY KEY (1)
└── payload: BLOB (encrypted vault payload — all record ciphertexts)
```

**Security properties:**
1. The record_directory is partially plaintext (type, size, offset). Acceptable trade-off for query performance.
2. The vault_blob is encrypted under VEK. Cannot be read without VEK.
3. Individual record isolation. Corrupting one record in the blob affects only that record.
4. SQLite WAL mode ensures atomic writes. Power loss during write cannot corrupt the database.
5. Integrity verification on vault unlock — corrupted records are flagged, not silently accepted.

### 10.2 Platform Secure Storage

| Platform | Mechanism | Use |
|---|---|---|
| Android | Keystore (KeyMint) + StrongBox | Store DUK private key, sharing keys, pairing keys. DUK wraps KEK cache. |
| Windows | DPAPI + TPM | Store DUK material. DPAPI binds to user + machine. |
| macOS | Keychain + Secure Enclave | Store DUK private key. SE performs key operations. |
| Linux | Secret Service API | Store DUK private key. Fallback: encrypted file. |

**Critical distinction:** Platform secure storage protects cryptographic keys and small secrets. The vault payload (potentially MB of encrypted records) lives in application private storage, encrypted with the VEK. This separation ensures that even if platform secure storage is compromised (rare), the vault remains encrypted under VEK.

---
