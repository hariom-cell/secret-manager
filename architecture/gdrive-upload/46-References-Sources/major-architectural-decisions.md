# Section 46: References, Sources & Major Architectural Decisions

**From:** Secret Manager — Complete Security Architecture
**Sources Section:** §46 + Full Document

---

## Major Architectural Decisions

| # | Decision | Rationale |
|---|---|---|
| 1 | **XChaCha20-Poly1305** for record encryption | 192-bit random nonces (no collision risk), consistent cross-platform performance, side-channel resistant. Over AES-GCM which needs careful nonce management. |
| 2 | **Argon2id (RFC 9106)** for KDF | Memory-hard, resists GPU/ASIC attacks, IETF standard, tunable parameters, widely available. Over PBKDF2 (not memory-hard) and scrypt (less analyzed). |
| 3 | **Per-record envelope encryption** with DEKs wrapped under VEK | Limits blast radius, enables per-record key rotation, fast VEK rotation without re-encrypting all plaintexts, record-level deletion with key zeroization. |
| 4 | **Application-level encryption** over SQLCipher | Enables per-record DEKs, granular key rotation, individual record corruption isolation, portable format, incremental migration. SQLCipher gives single-key all-or-nothing. |
| 5 | **Rust** for cryptographic core | Memory safety (no buffer overflows/use-after-free), `zeroize` crate for guaranteed key wiping, no GC pauses, deterministic memory management, FFI to all platform UIs. |
| 6 | **Biometrics as convenience unlock only** | Biometrics are not secrets, not consistent, not revocable. DUK wraps cached KEK. Master password remains root of trust. |
| 7 | **Local-first, serverless core** | No server required for any function. Optional zero-knowledge sync added later. Minimizes attack surface and operational complexity. |
| 8 | **Transport-agnostic sharing** with X25519 + Ed25519 | Self-encrypted packages. Any transport (WhatsApp, Signal, QR, NFC) carries only ciphertext. Ephemeral keys provide forward secrecy. |
| 9 | **Honest recovery model** | No backdoors. Recovery phrase IS a master password. Shamir SSS optional. User must control recovery material. |
| 10 | **HKDF-SHA256** for key derivation | RFC 5869 standard. Used for share key derivation from X25519 ECDH. Separates KDF from Argon2id (which is for password-based derivation only). |

---

## Standards References

| Standard | Title | Relevance |
|---|---|---|
| RFC 9106 | Argon2 Memory-Hard Function | Master password key derivation |
| RFC 8439 | ChaCha20-Poly1305 AEAD | Record encryption (XChaCha20 variant) |
| RFC 8032 | Edwards-Curve Digital Signature Algorithm (Ed25519) | Sharing package authentication, device pairing |
| RFC 7748 | Elliptic Curves for Security (X25519/X448) | Sharing key exchange, pairing |
| RFC 5869 | HMAC-based Extract-and-Expand Key Derivation Function | Share key derivation from ECDH |
| NIST SP 800-63B | Digital Identity Guidelines | Password strength, authentication guidelines |
| OWASP Password Storage Cheat Sheet | Password hashing best practices | Argon2id parameter recommendations |
| Android Keystore Docs | KeyMint / StrongBox | Hardware-backed key storage |
| Apple CryptoKit / Secure Enclave | Platform secure key storage | macOS/iOS key management |
| Microsoft DPAPI / Windows Hello | Windows credential protection | Desktop key storage |
| freedesktop.org Secret Storage | Secret Service API specification | Linux key storage standard |
| BIP-39 | Mnemonic code for generating deterministic keys | Recovery phrase generation |
| SLSA | Supply-chain Levels for Software Artifacts | Build attestation, provenance |

---

## Cryptographic Library References

| Library | Purpose | Platforms | Audit Status |
|---|---|---|---|
| libsodium (sodiumoxide) | Argon2id, XChaCha20, X25519, Ed25519, CSPRNG | All (via Rust) | Widely audited, production-grade |
| blake3 | Hashing, AAD computation | All (via Rust) | Audited, formal verification in progress |
| zeroize (Rust crate) | Secure memory zeroization | All (via Rust) | Simple, auditable |
| HKDF crate | Key derivation | All (via Rust) | Straightforward implementation |
| Android Keystore | Hardware-backed key storage | Android | Google-maintained |
| Apple CryptoKit | Platform key storage | macOS/iOS | Apple-maintained |
| CNG / DPAPI | Windows key storage | Windows | Microsoft-maintained |
| Secret Service API | Linux key storage | Linux | freedesktop.org standard |

---

## What We Do NOT Use and Why

| Primitive/Approach | Reason for Exclusion |
|---|---|
| PBKDF2 | Not memory-hard. GPU can compute billions/sec. Replaced by Argon2id. |
| scrypt | Memory-hard but less analysis, no RFC standard. Argon2id preferred. |
| AES-GCM (application-level) | Nonce management complexity. 96-bit nonce space has collision risk. XChaCha20 preferred. |
| AES-GCM-SIV | Misuse-resistant but ~30-50% slower. Unnecessary with XChaCha20's 192-bit nonces. |
| AES Key Wrap (RFC 3394) | Not universally available in mobile Keystore APIs. HMAC-SHA256 + AES-GCM preferred. |
| Custom cryptographic primitives | Kerckhoffs's Principle. Only standard, peer-reviewed algorithms. |
| RSA | Larger keys, slower, side-channel concerns. ECC preferred (X25519, Ed25519). |
| ECDSA | Deterministic signatures (Ed25519) preferred over ECDSA. |
| SHA-1 | Deprecated. SHA-256 used everywhere. |
| MD5 | Broken. Never used. |
| SQLCipher | Single-key encryption. No per-record granularity. Application-level preferred. |
| Proprietary key formats | Interoperability, auditability, standard compliance. |

---

## Known Limitations and Future Work

| Limitation | Future Direction |
|---|---|
| X25519/Ed25519 not post-quantum | Hybrid PQ-KEM (X25519 + ML-KEM-768) in protocol versioning |
| No formal protocol verification | Consider ProVerif or Tamarin for sharing/pairing protocols |
| Sync conflict resolution is basic | Operational transform or CRDT-based merging |
| Linux support deferred | Linux is Phase 3 of roadmap |
| No browser extension in MVP | Planned for Phase 8+ |
| No hardware security key in MVP | FIDO2/WebAuthn planned for Level 4 security |
| Side-channel analysis incomplete | Requires dedicated security review with timing/power analysis |
| No threshold signature scheme | Consider for enterprise/shared vault features |

---

## Document History

| Version | Date | Changes |
|---|---|---|
| 1.0 | September 2026 | Initial complete architecture study |

---

## License Note

This document is an internal engineering artifact. All cryptographic standards referenced are publicly available (IETF RFCs, NIST publications, OWASP guidelines).
