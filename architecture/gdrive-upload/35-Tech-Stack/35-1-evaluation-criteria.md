# 35.1 Evaluation Criteria

**Source:** §35 — Secret Manager Architecture Study

---

## 35. Recommended Technology Stack

### 35.1 Evaluation Criteria

| Criterion | Weight | Rationale |
|---|---|---|
| Cryptographic correctness | Critical | Must be auditable, use well-tested libraries |
| Memory safety | Critical | Prevent buffer overflows, use-after-free in crypto code |
| Cross-platform support | High | Android + Windows + macOS + Linux |
| Performance | High | Argon2id is CPU-intensive; XChaCha20 must be fast |
| Ecosystem maturity | High | Well-maintained libraries, active community |
| Developer productivity | Medium | Important but secondary to security |

### 35.2 Stack Recommendation

```
┌─────────────────────────────────────────────────────────────────┐
│                    RECOMMENDED TECH STACK                        │
│                                                                 │
│  CRYPTOGRAPHIC CORE (shared across all platforms)                │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  Language: Rust                                           │  │
│  │                                                            │  │
│  │  Libraries:                                               │  │
│  │  - libsodium (via sodiumoxide) — Argon2id, XChaCha20,     │  │
│  │    X25519, Ed25519, randombytes                           │  │
│  │  - HKDF: hkdf crate                                       │  │
│  │  - Memory zeroization: zeroize crate                      │  │
│  │  - BLAKE3: blake3 crate (hashing, AAD)                   │  │
│  │                                                            │  │
│  │  Build: cargo, with reproducible builds                   │  │
│  │  FFI: Generated via uniffi or cbindgen for platform interop│  │
│  └───────────────────────────────────────────────────────────┘  │
│                            │                                     │
│  ┌───────────────────────┼─────────────────────────────────┐   │
│  │                       ▼                                 │   │
│  │  ┌────────────────┐  ┌────────────────┐  ┌───────────┐ │   │
│  │  │   Android      │  │   Windows      │  │   macOS   │ │   │
│  │  │               │  │               │  │           │ │   │
│  │  │ Kotlin +      │  │ C#/.NET +     │  │ Swift +   │ │   │
│  │  │ Rust FFI      │  │ Rust FFI      │  │ Rust FFI  │ │   │
│  │  │               │  │               │  │           │ │   │
│  │  │ Jetpack       │  │ WinUI 3 /     │  │ SwiftUI / │ │   │
│  │  │ Compose UI    │  │ WPF UI        │  │ AppKit UI │ │   │
│  │  │               │  │               │  │           │ │   │
│  │  │ Room (SQLite) │  │ SQLite        │  │ SQLite    │ │   │
│  │  │ for structure │  │ (raw)         │  │ (raw)     │ │   │
│  │  └───────────────┘  └───────────────┘  └───────────┘ │   │
│  │                                                            │   │
│  │  ┌────────────────┐                                       │   │
│  │  │    Linux       │                                       │   │
│  │  │               │                                       │   │
│  │  │ Rust + GTK4   │                                       │   │
│  │  │ (or Tauri)    │                                       │   │
│  │  │               │                                       │   │
│  │  │ SQLite (raw)  │                                       │   │
│  │  └───────────────┘                                       │   │
│  └───────────────────────────────────────────────────────────┘   │
│                                                                 │
│  SHARED SERVICES (cross-platform)                               │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │  - SQLite for database structure                           │  │
│  │  - Platform Keystore integration (via Rust FFI)            │  │
│  │  - QR code generation/scanning                              │  │
│  │  - TOTP generation (HMAC-SHA1)                             │  │
│  │  - Password generator                                       │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

### 35.3 Why Rust for Crypto

1. **Memory safety.** No buffer overflows, no use-after-free, no null pointer dereferences. These are the #1 source of cryptographic vulnerabilities in C/C++.
2. **Zeroize support.** The `zeroize` crate provides guaranteed memory wiping that the compiler cannot optimize away.
3. **No GC.** Deterministic memory management. No garbage collection pauses. No GC-related copies of secrets.
4. **FFI compatibility.** Rust can compile to C-compatible libraries for use from Kotlin, Swift, C#.
5. **Performance.** Zero-cost abstractions. Comparable to C/C++.
6. **Growing ecosystem.** `sodiumoxide`, `aes-gcm`, `chacha20poly1305`, `argon2`, `ed25519-dalek`, `x25519-dalek` are mature crates.
7. **Auditability.** Rust code is easier to audit for memory safety than C/C++. The borrow checker enforces correctness.

**What stays native:**
- Android UI: Kotlin + Jetpack Compose
- macOS UI: Swift + SwiftUI
- Windows UI: C# + WinUI 3 (or WPF for broader compatibility)
- Linux UI: Rust + GTK4, or Tauri (Rust + webview)

**What is Rust:** All cryptographic operations, key management, vault encryption/decryption, record management, sharing protocol, device pairing, backup/restore.

---
