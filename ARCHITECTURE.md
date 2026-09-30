# Architecture

This document describes the crate layout, data flow, and key design decisions of Secret Manager.
Target audience: contributors and integrators who want to understand how the pieces fit together.

## Crate Map

```
secret-manager/
├── crates/
│   ├── vault-core/          Cryptographic primitives + vault format (pure Rust, no I/O)
│   ├── vault-db/            SQLite-backed encrypted record store
│   ├── vault-sdk/           High-level façade: backup, recovery, TOTP, password gen
│   ├── vault-linux/         Linux platform bindings (key store, secure input)
│   ├── vault-macos/         macOS platform bindings (Keychain, SecureInput)
│   ├── vault-android/       Android platform bindings (Keystore, BiometricPrompt)
│   ├── vault-windows/       Windows platform bindings (DPAPI, Credential Locker)
│   └── vault-cli/           CLI binary wrapping vault-sdk
├── fuzz/                    Standalone fuzz harnesses (no libfuzzer-sys)
└── Cargo.toml               Workspace root
```

### Crate Responsibilities

| Crate | Role | Notable deps |
|---|---|---|
| **vault-core** | AES-GCM / Argon2id / HKDF / formats / sessions | `chacha20poly1305`, `argon2`, `hmac`, `hkdf`, `sha2`, `zeroize`, `ed25519-dalek`, `x25519-dalek` |
| **vault-db** | Encrypted record storage over SQLite | `vault-core`, `rusqlite` (or `sqlx`) |
| **vault-sdk** | End-to-end user API (backup / recover / TOTP / gen-pass) | `vault-core`, `vault-db` |
| **vault-linux** | Linux platform adapters | `vault-sdk` |
| **vault-macos** | macOS platform adapters | `vault-sdk` |
| **vault-android** | Android platform adapters | `vault-sdk` |
| **vault-windows** | Windows platform adapters | `vault-sdk` |
| **vault-cli** | CLI entrypoint | `vault-sdk` |

## Dependency Direction

> **vault-core** → **vault-db** → **vault-sdk** → **vault-{linux,macos,android,windows}** → **vault-cli**

No crate imports from a higher layer. Platform crates depend only on `vault-sdk`, never on each other. This ensures:

- `vault-core` stays testable in isolation (no filesystem, no OS APIs).
- Each platform crate can be omitted or replaced without touching the core.
- `vault-cli` is the only binary in the default workspace build.

## Design Decisions

### 1. Application-Level Encryption

Encryption sits at the Rust layer, **above** SQLite. The database stores ciphertext; SQLite handles indexing, transactions, and backups. Decryption is lazy — only records needed by the current operation are decrypted. Implications:

- **Pro**: OS-level encryption (FileVault, LUKS, BitLocker) does not protect the SQLite database when unlocked. App-level encryption protects each record independently.
- **Pro**: DEK-per-record means removing a record destroys its key; data is unrecoverable without the DEK.
- **Con**: Must manage IVs and key derivation manually (done by the library).

### 2. Envelope Encryption

Rather than encrypting all records with one key, we use a three-layer hierarchy:

1. **KEK** — derived from the master password via Argon2id. Exists only in memory while the vault is unlocked.
2. **VEK** — random key material wrapped under the KEK. Stored in the vault file header. Regenerated on each unlock.
3. **DEK** — per-record keys derived via HKDF-SHA256 from the VEK. Never stored; re-derived from the VEK + record ID.

This means:

- **Changing the master password** only requires re-wrapping the VEK under a new KEK — no record re-encryption.
- **Deleting a record** removes its encrypted data; the DEK is not stored anywhere, so the record is irrecoverable.
- **VEK rotation** (every unlock) provides forward secrecy for new records.

### 3. Platform Abstraction via Traits

Cross-platform support is provided through traits defined in `vault-core::ffi`:

```rust
pub trait KeyStore { ... }
pub trait SecureInput { ... }
pub trait SystemClipboard { ... }
pub trait SessionPersistence { ... }
pub trait Platform { ... }
```

Each platform crate implements these traits. The `Platform` trait bundles them, and `vault-sdk` composes the implementations. The CLI ships a noop `Platform` that reads the password from stdin and never persists session tokens.

### 4. Fuzzing Without Nightly

Fuzz harnesses in `fuzz/` are ordinary binaries that accept iteration counts or byte slices via CLI arguments. They do not depend on `libfuzzer-sys`. This choice:

- Avoids the nightly Rust toolchain requirement.
- Lets CI run the harnesses with `cargo run -p vault-fuzz --bin <name> -- <iterations>`.
- Provides regression coverage even without a continuous fuzzing service.

## Data Flow

### Unlock (create / unlock command)

```
User password
    │
    ▼  Argon2id (password + salt + params)
   KEK bytes
    │
    ▼  AES-GCM unwrap (KEK + VEK nonce + wrapped VEK)
   VEK bytes
    │
    ▼  HKDF-SHA256 (VEK + record_id)  [per record as needed]
   DEK bytes
    │
    ▼  XChaCha20-Poly1305 (DEK + nonce + ciphertext)
   plaintext
```

### Lock (lock command)

```
1. Zeroize VEK in memory.
2. Zeroize all cached DEKs.
3. Zeroize session token.
4. Close vault file handle.
```

### Record write (set command)

```
1. Generate random DEK via HKDF-SHA256(VEK, record_id).
2. Encrypt payload with XChaCha20-Poly1305(DEK).
3. Wrap DEK in place (XChaCha20-Poly1305(KEK)).
4. Store [wrapped_DEK | nonce | ciphertext | tag] as EncryptedRecord.
5. Persist to SQLite.
```

### Record read (get command)

```
1. Retrieve EncryptedRecord from SQLite.
2. Unwrap DEK via HKDF-SHA256(VEK, record_id) — re-derived, never stored.
3. Decrypt with XChaCha20-Poly1305(DEK, nonce, ciphertext).
4. Return plaintext.
```

### Backup (export command)

```
1. Read entire vault file.
2. Sign with sender Ed25519 signing key.
3. Package as serialized ShareEnvelope.
4. Write to user-specified output path.
```

### Recovery (import command)

```
1. Parse ShareEnvelope.
2. Verify sender Ed25519 signature.
3. Derive shared secret via X25519(sender_public, recipient_private).
4. Unwrap DEK from envelope.
5. Insert recovered record into local vault.
```

## Vault File Format

See also `SECURITY.md#vault-file-format`.

```
Offset  Size  Field
─────── ──── ────────────────────────────────────────
0       4     MAGIC ('V' 'L' 'T' 1)
4       1     FORMAT_VERSION (0x01)
5       1     FLAGS (reserved)
6       2     Reserved (0)
8       1     KDF m_cost log2 (19 → 19 MiB)
9       1     KDF t_cost
10      1     KDF p_cost
11      1     VERSION_LEN (N)
12      N     VERSION (ASCII)
12+N    16    SALT (random per vault)
28+N    24    VEK_NONCE
52+N    32    VEK_CIPHERTEXT (VEK wrapped under KEK)
84+N    32    HMAC (HMAC-SHA256 over header + VEK wrap + records)
116+N   ...   RECORDS (variable-length array)
```

All multi-byte fields are native-endian. The HMAC covers everything from offset 0 to the end of the last record.

## Memory Layout

Key types and their zeroization guarantees:

| Type | Zeroizes on drop | Mlocked | Purpose |
|---|---|---|---|
| `KeyBytes` | ✅ | ✅ | Raw 32-byte key material |
| `SecureBuffer<32>` | ✅ | ✅ | Variable-size sealed buffer |
| `SecureString` | ✅ | ✅ | Password / passphrase |
| `Vek` | ✅ | ✅ | Vault encryption key |
| `WrappedDek` | ✅ | — | Encrypted DEK (no mlock needed) |
| `SessionToken` | ✅ | — | Session identifier |
| `SenderSigningKey` | ✅ | — | Ed25519 signing key |

## Test Strategy

| Layer | Tool | Count |
|---|---|---|
| Unit tests | `cargo test` | ~100+ per crate |
| Integration tests | `cargo test --test integration` | End-to-end vault CRUD |
| Fuzz | `cargo run -p vault-fuzz` | 1 000+ iterations per harness per run |
| CI | GitHub Actions | Lint (rustfmt + clippy), test (3 OSes), audit (cargo-audit + cargo-deny), build (6 targets), fuzz |

## Future Directions

- **Hardware token support** (U2F/FIDO2 for KEK storage).
- **Syncing via an end-to-end encrypted channel** (WebRTC / WebTorrent).
- **Vault splitting** (Shamir's Secret Sharing for recovery).
- **Audit logging** (append-only HMAC chain of operations).
- **WebAssembly target** (browser frontend using `vault-core` via wasm-pack).