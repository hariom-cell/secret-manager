# 36.1 Recommended Libraries

**Source:** §36 — Secret Manager Architecture Study

---

## 36. Cryptographic Libraries

### 36.1 Recommended Libraries

| Platform | Library | Purpose | Audit Status |
|---|---|---|---|
| All (via Rust) | libsodium (sodiumoxide) | Argon2id, XChaCha20-Poly1305, X25519, Ed25519, CSPRNG | Widely audited, used by thousands of projects |
| All (via Rust) | blake3 | Hashing, AAD computation | Audited, formal verification in progress |
| Android (native) | Android Keystore | Hardware-backed key storage | Google-maintained |
| Android (native) | Conscrypt | TLS, additional crypto | OpenJDK-maintained |
| Windows (native) | CNG / DPAPI | Platform key storage | Microsoft-maintained |
| macOS (native) | CryptoKit / Security.framework | Platform key storage | Apple-maintained |
| Linux (native) | Secret Service API | Platform key storage | freedesktop.org standard |

### 36.2 What We Do NOT Implement

- No custom cryptographic primitives
- No custom RNG
- No custom key derivation functions
- No custom encryption modes
- No custom signature schemes

All primitives come from independently audited, widely-used libraries.

---
