# Secret Manager — What It Does

## In One Sentence

A zero-knowledge, local-first encrypted vault that stores your secrets on disk,
protected by Argon2id + XChaCha20-Poly1305, with no server, no cloud sync,
and no way to recover your data without your master password.

---

## Core Problem It Solves

You have passwords, API keys, TOTP seeds, recovery phrases, certificates —
sensitive data scattered across password managers you don't fully trust,
browser profiles, notes files, and text messages. Most tools sync to a cloud
you don't control. This app keeps everything encrypted on *your* disk and
never sends it anywhere.

---

## What You Can Do With It

### 1. Create an encrypted vault

```
vault-cli create myvault.enc
```

- Generates a random 32-byte salt and a random 32-byte Vault Encryption Key (VEK)
- Derives a Key Encryption Key (KEK) from your master password using Argon2id
- Wraps (encrypts) the VEK with the KEK
- Writes a 256-byte header to disk: magic bytes, KDF parameters, salt, wrapped VEK, HMAC tag
- The master password is never written to disk

### 2. Store secrets

```
vault-cli set myvault.enc aabbccddeeff00112233445566778899 "my-api-key"
```

- Derives a per-record Data Encryption Key (DEK) from the VEK + record ID using HKDF-SHA256
- Encrypts the value with XChaCha20-Poly1305 (random 24-byte nonce per record)
- Appends the encrypted record to the vault file
- Different record IDs produce different DEKs — same value encrypted under different IDs is indistinguishable

### 3. Retrieve secrets

```
vault-cli get myvault.enc aabbccddeeff00112233445566778899
```

- Re-derives the KEK from your password (Argon2id verifies against HMAC first — wrong password is rejected before decryption)
- Unwraps the VEK
- Derives the record's DEK
- Decrypts and prints the plaintext

### 4. List, delete, generate passwords

- `list` — shows all record IDs (hex strings) in the vault
- `delete` — removes a record and rewrites the vault file
- `gen-pass` — generates cryptographically secure random passwords with configurable length and character classes

### 5. Change master password (rekey)

- Re-derives KEK from the new password
- Re-wraps the VEK under the new KEK
- Old password is zeroized; the file on disk now requires the new password

---

## Security Architecture

```
User types password
      │
      ▼
┌─────────┐    Argon2id     ┌─────┐
│ password │───────────────►│ KEK │
└─────────┘                 └──┬──┘
                               │ unwraps
                               ▼
                            ┌─────┐
                            │ VEK │  (32 bytes, random, stored wrapped)
                            └──┬──┘
                               │ HKDF-SHA256(record_id)
                               ▼
                            ┌─────┐    XChaCha20-Poly1305
                            │ DEK │────────────────► ciphertext
                            └─────┘
```

### Each secret is independently encrypted

Every record gets its own DEK derived from the VEK + that record's ID.
Compromising one record's ciphertext doesn't help attack any other record.

### Keys are never stored in plaintext

- VEK: stored wrapped (encrypted) under the KEK
- KEK: never stored — re-derived from password every time
- DEK: never stored — derived on-the-fly when needed
- All keys are zeroized in memory when the vault is locked or the process exits

### Tamper detection

HMAC-SHA256 over the header is verified before any decryption.
Any byte flipped in the vault file causes unlock to fail.

### Memory hygiene

- `zeroize` crate used on all key material, passwords, and plaintext values
- Clipboard auto-clears secrets after a timeout
- Debug format implementations hide sensitive key bytes

---

## File Format

```
┌──────────────────────────────────────────────────┐
│ HEADER (256 bytes, fixed)                         │
│  "VLT1"        [4]   magic                        │
│  0x0001        [2]   version (big-endian)         │
│  0x0000        [2]   reserved                     │
│  m_cost        [4]   Argon2id memory cost         │
│  t_cost        [4]   Argon2id time cost           │
│  p_cost        [4]   Argon2id parallelism          │
│  salt          [32]  random salt for KDF          │
│  wrapped_vek   [72]  nonce(24) + ct(48)           │
│  hmac          [32]  HMAC-SHA256 over header      │
│  reserved      [100] zero padding                 │
├──────────────────────────────────────────────────┤
│ RECORDS (variable)                                │
│  record_id [16]                                   │
│  ct_len    [4]   u32 big-endian                   │
│  nonce     [24]                                   │
│  ciphertext [ct_len] (XChaCha20-Poly1305 output)  │
│  ... (repeated for each record)                   │
└──────────────────────────────────────────────────┘
```

Default location: `~/.config/secret-manager/vault.enc`

---

## What It Does NOT Do

| Not supported | Why |
|--------------|-----|
| Cloud sync | Privacy-first design — your vault never leaves your machine |
| Password recovery | Zero-knowledge — if you forget the password, the data is cryptographically unrecoverable |
| Multi-device | Each device needs its own vault; sharing requires manual backup import |
| Browser autofill | No browser extension yet (WASM/web-app scaffolded, not complete) |
| Biometric unlock | Master password is the only secret; biometrics would need a device-specific key store |
| Social recovery | Conflicts with zero-knowledge guarantee |

---

## Deployment Targets

| Target | Status | How |
|--------|--------|-----|
| **macOS CLI** | Working | `cargo build --release --bin vault-cli` |
| **Linux CLI** | Works | Same build, musl target for static binary |
| **Windows CLI** | Works | Same build, mingw target |
| **Web (WASM)** | Code written | `wasm-pack build --target web` — blocked by sandbox on this machine |
| **Browser Extension** | Scaffolded | Manifest V3, needs icon assets |
| **PWA** | Scaffolded | Service worker + manifest, needs build verification |

---

## Current State

**Working today:**
- Full encryption/decryption pipeline (Argon2id → KEK → VEK → DEK → XChaCha20-Poly1305)
- CLI with create/unlock/list/get/set/delete/export/import/gen-pass
- HMAC integrity verification on every unlock
- 116 unit tests + 17 integration tests passing
- Password generator with entropy calculation
- Backup/restore (export/import)
- TOTP module (RFC 6238) in SDK (not yet wired to CLI)
- Recovery phrase module in SDK (not yet wired to CLI)
- WASM bindings written (needs wasm-pack build)
- Install scripts (Homebrew, apt, curl-pipe-bash)
- Homebrew formula, apt repo setup, DEB packaging

**Not yet wired up:**
- TOTP code generation in the CLI (`vault-cli totp <record-id>`)
- Recovery phrase display/import in the CLI
- Auto-type (paste secrets to focused window)
- Web app build verification
- GitHub Releases for binary distribution
- `cargo audit` / `cargo deny` (network blocked in sandbox)

---

## Threat Model

**Protected against:**
- Theft of the vault file — requires the master password to decrypt
- Tampering with the vault file — HMAC rejects modifications
- Memory scraping after lock — keys are zeroized
- Brute-force — Argon2id is intentionally slow (configurable cost params)
- Rainbow tables — unique 32-byte salt per vault
- Ciphertext analysis — XChaCha20-Poly1305 is IND-CCA secure

**Not protected against:**
- Keyloggers capturing the master password as you type it
- A compromised OS that reads memory while the vault is unlocked
- Someone with physical access while the vault is unlocked in memory
- You forgetting the master password (no backdoor, no recovery)
