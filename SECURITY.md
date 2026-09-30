# Security Policy

This document describes the security goals, threat model, and cryptographic design of Secret Manager.
If you believe you have found a vulnerability, please follow the [Vulnerability Reporting](#vulnerability-reporting) section below.

## Our Security Goals

Secret Manager is designed around four guarantees:

1. **Confidentiality at rest** — Vault contents are unreadable without the master password, even to an attacker with full filesystem access.
2. **Authenticated encryption** — Every modification to a vault file is authenticated. Tampering is detected and rejected.
3. **Memory hygiene** — Sensitive material is zeroized on drop and never persisted in swap or core dumps.
4. **Forward secrecy per record** — Compromising one record's key does not compromise other records.

## Threat Model

### In Scope

The following adversaries are explicitly considered:

- **Local file attacker** — Has read access to the encrypted vault file (e.g., stolen disk, unencrypted backup, cloud sync of the vault file). Cannot decrypt without the master password.
- **Local privileged attacker** — Has read access to the running process memory while the vault is unlocked (e.g., admin user, another process via `/proc/<pid>/mem`). Mitigations are best-effort — see [Limitations](#limitations).
- **Network attacker** — Cannot perform meaningful attacks because Secret Manager does not transmit vault data over the network by design.
- **Active file tampering** — Modifies bytes in the vault file to attempt forgery or rollback. Detected and rejected by HMAC verification.

### Out of Scope

- **Compromised endpoint with live unlocked vault** — If your device is compromised while the vault is unlocked, an attacker may read the unlocked buffer. Use auto-lock.
- **Weak master password** — A short or guessable password defeats the KDF. Use `vault-cli gen-pass` to generate a strong one.
- **Side channels against `XChaCha20-Poly1305`** — The cryptographic primitives are constant-time; we do not claim immunity against hardware-level side channels.
- **Supply chain attacks on build infrastructure** — Builds are reproducible (see below); users should verify signatures.

## Cryptographic Design

### Algorithms

| Purpose | Algorithm | Standard |
|---|---|---|
| Master password → KEK | Argon2id | RFC 9106 |
| Envelope encryption | XChaCha20-Poly1305 | RFC 8439 |
| Per-record key derivation | HKDF-SHA256 | RFC 5869 |
| Vault file integrity | HMAC-SHA256 | RFC 2104 |
| Sharing | X25519 + Ed25519 | RFC 7748 / RFC 8032 |
| TOTP | RFC 6238 | RFC 6238 |
| Password generation | ChaCha12 CSPRNG | — |

### Key Hierarchy

```
Master Password
    │
    ▼  Argon2id (m_cost, t_cost, p_cost)
   KEK  (Key Encryption Key)
    │
    ▼  AES‑GCM wrap (or XChaCha20‑Poly1305)
   VEK  (Vault Encryption Key) — random, rotated by re-unlock
    │
    ▼  HKDF‑SHA256 (info = record_id)
   DEK  (Data Encryption Key) — per record, ephemeral
    │
    ▼  XChaCha20‑Poly1305
 Record ciphertext
```

### Minimum KDF Parameters

The library **rejects** configurations below these floors to prevent downgrade attacks against brute force:

| Parameter | Floor | Meaning |
|---|---|---|
| `m_cost` (KiB) | 19 552 | ~19 MiB of memory per derivation |
| `t_cost` | 2 | Iterations |
| `p_cost` | 1 | Parallelism (lanes) |

These values match OWASP's recommended Argon2id floor for interactive use. Servers with HMAC hardware may want higher; client devices should not go lower.

### Memory Hygiene

- Every type that holds key material implements [`Zeroize`](https://docs.rs/zeroize) and [`ZeroizeOnDrop`].
- On Unix, key buffers are `mlock(2)`-ed so they never hit swap.
- The `SecureBuffer` type combines mlock + zeroize + bound checking.
- Anti-debug checks (Linux `ptrace`, Windows `IsDebuggerPresent`) refuse to unlock when a debugger is attached. Disable for testing only.
- Auto-lock timer zeroes all keys after configurable inactivity.

### Constant-Time Operations

All comparisons of secret-derived material (MACs, wrapped keys, password hashes) use a constant-time XOR-and-OR comparison. See [`ct_eq`] in the source. Never compare secrets with `==`.

### Vault File Format

A vault file is:

```
┌─────────────┬─────────────────────────────────────────┐
│ Header      │ MAGIC │ VERSION │ KDF_PARAMS │ SALT │   │
│ (64 bytes)  │       │         │ (m,t,p)    │(16)  │   │
├─────────────┼─────────────────────────────────────────┤
│ VEK wrap    │ nonce(24) │ ciphertext(32) │ tag(16) │  │
├─────────────┼─────────────────────────────────────────┤
│ Records[]   │ per record: wrapped_dek │ nonce │ ct   │  │
├─────────────┼─────────────────────────────────────────┤
│ HMAC        │ HMAC-SHA256(header ‖ VEK_wrap ‖ records)│
└─────────────┴─────────────────────────────────────────┘
```

- Magic bytes: `VLT1` (4 bytes).
- A 64-byte fixed header.
- An integrity HMAC over the entire authenticated region.
- The verifier rejects any mismatch.

### Fuzzing

Two fuzz harnesses run continuously in CI:

- `fuzz_format_parse` — feeds random bytes into the header/record parser. Cross-checks consistency between header parsers and asserts KDF parameters are non-zero from well-formed headers.
- `fuzz_aead_roundtrip` — exercises encrypt/decrypt roundtrip, tampered ciphertext rejection, wrong-key rejection.

Both harnesses run on stable Rust and execute thousands of iterations per CI run.

## Known Limitations

- **Live process memory** — An attacker with read access to the running process while the vault is unlocked can read the unlocked buffer. Mitigations are best-effort (mlock, anti-debug, auto-lock).
- **No hardware token support yet** — U2F/WebAuthn/FIDO2 will be added in a future release. Until then, the master password is the single factor.
- **Clipboard** — Auto-clearing the system clipboard depends on the OS honoring the clear. Some clipboard managers preserve history.
- **Memory dumps on crash** — `panic = "abort"` is enabled in release builds so a panic does not produce a core dump containing in-memory secrets.

## Vulnerability Reporting

**Please do not file a public issue.** Email security@secret-manager.example.com with:

1. A description of the vulnerability and impact.
2. Steps to reproduce.
3. Affected versions.
4. Whether you intend to disclose publicly, and your timeline.

We acknowledge within 72 hours and aim to ship a fix within 30 days for critical issues. We coordinate disclosure timing with reporters.

## Supported Versions

| Version | Supported |
|---|---|
| Latest release | ✅ |
| Previous release | ✅ (security fixes backported) |
| Older | ❌ |

## Cryptographic Library Audits

The crate depends on:

- `chacha20poly1305` — audited as part of the RustCrypto org.
- `argon2` — reference impl of RFC 9106.
- `ed25519-dalek`, `x25519-dalek` — widely audited.
- `hmac`, `hkdf`, `sha2` — RustCrypto primitives.

No formal third-party audit has been commissioned at the time of writing. Audit reports will be linked here when available.

## Reproducible Builds

Release artifacts are built with:

- `SOURCE_DATE_EPOCH` pinned to the release tag commit time.
- `lto = "fat"`, `codegen-units = 1`, `panic = "abort"`, `strip = true`, `opt-level = "z"`.
- `cargo build --locked` (dependencies pinned in `Cargo.lock`).

The `scripts/build_repro.sh` script builds twice and diffs `sha256` of executables. Reproducible-build verification is part of the release checklist.