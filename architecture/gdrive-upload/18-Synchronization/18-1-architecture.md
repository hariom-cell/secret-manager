# 18.1 Architecture

**Source:** §18 — Secret Manager Architecture Study

---

## 18. Optional Synchronization

### 18.1 Architecture

```
DEVICE A ──[encrypted package]──▶ Cloud Storage ◀──[encrypted package]── DEVICE B
                              (Google Drive, OneDrive, Dropbox, iCloud, S3)

Cloud sees: encrypted packages only. No VEK. No KEK. No plaintext.
```

### 18.2 Sync Package Format

```
┌──────────────────────────────────────────────────────────────────┐
│ Field              │ Type      │ Description                     │
├──────────────────────────────────────────────────────────────────┤
│ version            │ uint16    │ Protocol version                │
│ device_id          │ bytes     │ Unique device identifier        │
│ vault_version      │ uint64    │ Monotonic version counter       │
│ timestamp          │ uint64    │ Unix timestamp of sync          │
│ base_version       │ uint64    │ Version this delta is based on  │
│ encrypted_payload  │ bytes     │ VEK-encrypted vault delta       │
│ payload_nonce      │ bytes     │ XChaCha20 nonce                 │
│ payload_tag        │ bytes     │ Poly1305 tag                    │
│ device_signature   │ bytes     │ Ed25519 sig of package          │
│ hash_chain         │ bytes     │ Previous package hash           │
└──────────────────────────────────────────────────────────────────┘
```

### 18.3 Conflict Resolution

- Each record has a version vector (device_id, counter).
- Compare version vectors on merge.
- Highest counter wins (last-write-wins per record).
- Concurrent modifications to same record: flag for manual resolution.
- **Recommendation:** Last-write-wins + manual conflict flagging. What Bitwarden and 1Password do.

### 18.4 Security Properties

| Property | Implementation |
|---|---|
| Server cannot read secrets | All packages encrypted under VEK |
| Replay protection | Monotonic version counter + hash chain |
| Tamper detection | Device signature on every package |
| Deleted records | Tombstone records with version vectors |
| Rollback prevention | Hash chain references previous hash |

### 18.5 Sync Provider Options

| Provider | Security | Practicality |
|---|---|---|
| Google Drive | Good (E2E encrypted) | Excellent |
| OneDrive | Good | Good (Microsoft ecosystem) |
| Dropbox | Good | Good (version history) |
| iCloud | Good | Good (Apple ecosystem) |
| S3-compatible | Good | Good (self-hostable) |
| Own server | Good | Requires infrastructure |
| P2P (WebRTC) | Excellent | Both devices must be online |

**Recommendation:** Support multiple providers. The sync layer is agnostic to storage backend.

---
