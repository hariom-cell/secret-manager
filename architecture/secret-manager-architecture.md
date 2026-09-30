# Privacy-First Secret Manager — Complete Security Architecture & Implementation Study

**Version:** 1.0 — September 2026
**Classification:** Internal Engineering Document
**Status:** Pre-Implementation Design Review

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Security Principles](#2-security-principles)
3. [Threat Model](#3-threat-model)
4. [Trust Boundaries](#4-trust-boundaries)
5. [Cryptographic Architecture](#5-cryptographic-architecture)
6. [Key Hierarchy](#6-key-hierarchy)
7. [Key Lifecycle](#7-key-lifecycle)
8. [Master Password & Authentication](#8-master-password--authentication)
9. [Record Encryption](#9-record-encryption)
10. [Encrypted Local Database](#10-encrypted-local-database)
11. [Metadata Privacy](#11-metadata-privacy)
12. [Android Security Architecture](#12-android-security-architecture)
13. [Desktop Security Architecture](#13-desktop-security-architecture)
14. [Biometric Authentication](#14-biometric-authentication)
15. [No-Server Secret Sharing Protocol](#15-no-server-secret-sharing-protocol)
16. [WhatsApp as Transport Layer](#16-whatsapp-as-transport-layer)
17. [Device-to-Device Pairing](#17-device-to-device-pairing)
18. [Optional Synchronization](#18-optional-synchronization)
19. [Backup & Recovery](#19-backup--recovery)
20. [Password Generator](#20-password-generator)
21. [TOTP / 2FA](#21-totp--2fa)
22. [Autofill Architecture](#22-autofill-architecture)
23. [Memory Security](#23-memory-security)
24. [Clipboard Security](#24-clipboard-security)
25. [Secure UI](#25-secure-ui)
26. [Security Levels](#26-security-levels)
27. [Hardware Security Keys](#27-hardware-security-keys)
28. [Account Model](#28-account-model)
29. [Serverless vs Server-Based](#29-serverless-vs-server-based)
30. [Supply Chain Security](#30-supply-chain-security)
31. [Logging & Telemetry](#31-logging--telemetry)
32. [Update Security](#32-update-security)
33. [Database Corruption & Recovery](#33-database-corruption--recovery)
34. [Performance Analysis](#34-performance-analysis)
35. [Recommended Technology Stack](#35-recommended-technology-stack)
36. [Cryptographic Libraries](#36-cryptographic-libraries)
37. [Data Model](#37-data-model)
38. [Package Formats](#38-package-formats)
39. [Cryptographic Migration](#39-cryptographic-migration)
40. [Red-Team Analysis](#40-red-team-analysis)
41. [Security Theater Avoidance](#41-security-theater-avoidance)
42. [Development Roadmap](#42-development-roadmap)
43. [MVP Definition](#43-mvp-definition)
44. [Security Audit Checklist](#44-security-audit-checklist)
45. [Formal Protocol Specifications](#45-formal-protocol-specifications)
46. [Final Deliverables & Status](#46-final-deliverables--status)

---

## 1. Executive Summary

This document defines the complete security architecture for a commercial-grade, privacy-first Secret Manager application targeting Android, Windows, macOS, and Linux. The product's foundational guarantee: **the application developer/operator must never have access to user plaintext secrets**, even in the event of infrastructure compromise.

### Core Architectural Decisions

1. **Local-first, serverless core.** Every cryptographic operation happens on the user's device. No server is required for any core function. Cloud sync, if offered, is an optional zero-knowledge layer.

2. **Key hierarchy with Argon2id-derived root key.** The master password never leaves the device in plaintext. It is transformed via Argon2id (RFC 9106) into a Key Encryption Key (KEK), which encrypts a randomly generated Vault Encryption Key (VEK). Data is encrypted with the VEK.

3. **Per-record envelope encryption.** Each secret record has its own unique Data Encryption Key (DEK), wrapped by the VEK. This limits blast radius and enables key rotation without re-encrypting the entire vault.

4. **Authenticated encryption everywhere.** XChaCha20-Poly1305 (RFC 8439) for record encryption; HMAC-SHA256 for authenticated key wrapping.

5. **Biometric authentication is a convenience unlock, not a cryptographic root.** Biometrics authorize release of a device-protected key; they do not replace or weaken the master password's role.

6. **Transport-agnostic sharing.** Secret sharing uses self-encrypted packages with X25519 (RFC 7748) key exchange. WhatsApp, Signal, email, QR, NFC, or any transport carries only ciphertext.

7. **Realistic threat model.** This document explicitly states what the architecture protects against and what it does not. No claim of "100% security" is made.

### What This Architecture Guarantees

- If the encrypted vault file is stolen, plaintext cannot be recovered without the master password or recovery material.
- If the database is stolen from a compromised server, plaintext cannot be recovered.
- If a backup is intercepted, plaintext cannot be recovered.
- If sync infrastructure is compromised, plaintext cannot be recovered.
- A malicious developer, DBA, or cloud provider cannot recover plaintext.

### What This Architecture Does NOT Guarantee

- Protection against malware on the same device with user-level access (keyloggers, screen scrapers, memory access).
- Protection against the user being tricked into revealing their master password.
- The ability to recover a vault if the user loses ALL cryptographic recovery material (zero-knowledge means no backdoor).
- Absolute prevention of memory extraction on a running device (mitigation only).
- Protection against quantum computers breaking X25519/ECDSA (addressed via protocol versioning for future post-quantum migration).

---

## 2. Security Principles

### P1: Zero-Knowledge by Default
The application developer never possesses any material from which plaintext can be derived. This is a property of the cryptographic architecture, not a policy.

### P2: Local-First Operation
All core functionality (unlock, create, read, update, delete, search, generate TOTP) must work without any network connection. External services are optional enhancements, never prerequisites.

### P3: Cryptographic Agility
Algorithms, key sizes, and KDF parameters must be migratable. The vault format carries versioning and algorithm identifiers so future upgrades do not require plaintext exposure.

### P4: Defense in Depth
Multiple independent layers of protection. Failure of one layer does not compromise the whole system.

### P5: Minimal Trusted Computing Base
The security-critical path (key derivation, encryption, decryption) should be implemented in as small and auditable a surface as possible.

### P6: Fail-Safe Defaults
Default settings maximize security. Security-weakening options must be explicitly opt-in.

### P7: Honest Security Claims
Marketing language must not overstate protection. Users must be informed of genuine limitations.

### P8: Cryptographic Correctness Over Convenience
When security and convenience conflict, the architecture chooses security and makes the convenience cost explicit.

---

## 3. Threat Model

### 3.1 Threat Definitions

| ID | Threat | Attack Method | Assets | Prob. | Impact | Mitigation |
|---|---|---|---|---|---|---|
| T01 | Stolen locked phone | Attacker picks up unlocked device | All secrets | Medium | Critical | Auto-lock, biometric/device credential re-auth |
| T02 | Stolen unlocked phone | Attacker takes device while app unlocked | All secrets | Medium | Critical | Short auto-lock timeout, memory zeroization on lock |
| T03 | Stolen encrypted vault file | Database extraction via backup, sync, or file system access | Encrypted vault | High | Low (without password) | Argon2id KDF, strong master password |
| T04 | Offline brute-force | Attacker has vault file, performs dictionary attack | Encrypted vault | High | Medium | Argon2id with high memory cost (≥128 MB) |
| T05 | Malware on device | Keylogger, screen scraper, memory dumper | All secrets in use | Medium | Critical | Screen protection, clipboard auto-clear, memory zeroization |
| T06 | Rooted Android | Privilege escalation reads app data, key material | All secrets | Low | Critical | Detect root, warn user, hardware-backed keystore |
| T07 | Compromised desktop | Malware with user privileges | All secrets in use | Medium | Critical | OS keychain for key wrapping, minimize plaintext lifetime |
| T08 | Cloud sync compromise | Attacker gains read access to sync storage | Encrypted packages | Medium | Low | End-to-end encryption, sync server never sees keys |
| T09 | Compromised backup | Attacker obtains backup file | Encrypted backup | Low | Low | Encrypted backup, separate password |
| T10 | Malicious sharing recipient | Recipient stores and forwards shared secret | Shared secrets | Medium | Medium | Per-package ephemeral keys, user awareness |
| T11 | MITM during sharing | Intercept/alter package in transit | Shared secrets | Low | Medium | Ed25519 sender auth, key confirmation |
| T12 | Phishing (autofill) | Malicious site receives autofilled credentials | Credentials | Medium | High | Domain verification, user confirmation, no silent autofill |
| T13 | Device loss (no backup) | User loses device with vault | All secrets | Low | Critical | Encrypted backup, recovery phrase |
| T14 | Forgotten master password | User cannot derive keys | All secrets | Low | High | Recovery phrase, Shamir Secret Sharing |
| T15 | Evil Maid | Physical access to powered-off device | Encrypted vault | Low | Medium | TPM/SE binding, hardware-backed keys |
| T16 | Malicious update | Compromised update delivers trojan | All secrets | Low | Critical | Signed updates, reproducible builds |
| T17 | Supply-chain attack | Compromised dependency introduces backdoor | All secrets | Low | Critical | SBOM, dependency pinning, fuzzing |
| T18 | Dependency compromise | Popular library compromised | All secrets | Low | Critical | Minimal dependencies, auditing |
| T19 | Memory extraction | Cold boot, DMA, debugging | Plaintext in RAM | Low | Critical | Short-lived plaintext, immutable buffers, zeroization |
| T20 | Clipboard exposure | Malicious app reads clipboard | Last-copied secret | Medium | Medium | Auto-clear, clipboard monitoring |
| T21 | Screenshots/screen recording | Capture of app screen | All visible secrets | Medium | Medium | FLAG_SECURE, screenshot blocking |
| T22 | Brute-force on TOTP | Attacker guesses 6-digit TOTP | Individual TOTP account | High | Low (TOTP designed for this) | TOTP rate-limited by design; app auto-clear |
| T23 | Database corruption | Power loss, crash during write | Some records | Medium | Low | Per-record encryption, WAL, atomic transactions |
| T24 | Rogue paired device | Unauthorized device pairs and exfiltrates | Vault data | Low | High | Human-verified pairing codes, device revocation |
| T25 | Compromised sharing transport | WhatsApp/Signal server compromise | Package metadata only | Low | Low | Transport carries only ciphertext |
| T26 | Quantum future | Quantum computers break X25519/ECDH | All encrypted data | Low | Future | Protocol versioning for post-quantum migration |

### 3.2 What We Protect Against

- Stolen device (locked or unlocked, up to cold boot attacks — partially)
- Stolen database file or backup
- Network interception of sync or share packages
- Compromised cloud server or sync service
- Malicious employee with database access
- Supply-chain attacks on dependencies (mitigated, not eliminated)
- Phishing via autofill

### 3.3 What We Explicitly Do NOT Protect Against

- Malware running with user privileges on the same device (keyloggers, screen scrapers, memory access). This is an OS-level problem.
- The user being tricked into revealing their master password.
- Forensic analysis of the unlocked app's memory by an attacker with physical device access and debugging capabilities.
- A user who has no recovery material regaining access to their vault.
- Quantum computers breaking X25519/ECDSA (addressed via versioning).

---

## 4. Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────┐
│                     TRUSTED BOUNDARY                             │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              SECRET MANAGER APPLICATION                    │  │
│  │  ┌────────────┐  ┌──────────────┐  ┌──────────────────┐   │  │
│  │  │   Crypto   │  │   Vault      │  │   UI /           │   │  │
│  │  │   Engine   │  │   Manager    │  │   Autofill       │   │  │
│  │  └────────────┘  └──────────────┘  └──────────────────┘   │  │
│  │       │                │                  │                │  │
│  │  ┌────┴────────────────┴──────────────────┴───────┐        │  │
│  │  │           Platform Secure Storage                │        │  │
│  │  │  (Keystore / Keychain / DPAPI / Secret Service)  │        │  │
│  │  └──────────────────────────────────────────────────┘        │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                              │                                    │
│                ┌─────────────┴──────────────┐                    │
│                ▼                             ▼                    │
│  ┌──────────────────────┐    ┌──────────────────────────┐        │
│  │   USER INPUT         │    │  EXTERNAL TRANSPORT        │        │
│  │  (master pw,         │    │  (WhatsApp, Signal, QR,    │        │
│  │   biometrics)        │    │   NFC, Bluetooth)          │        │
│  └──────────────────────┘    └──────────────────────────┘        │
│                                    │  TRUSTED FOR TRANSPORT ONLY  │
│                                    │  Never trusts plaintext      │
│                                    ▼                               │
│  ┌───────────────────────────────────────────────────────────┐    │
│  │  OPTIONAL CLOUD (Sync server)                             │    │
│  │  Sees only encrypted packages. Cannot derive keys.        │    │
│  └───────────────────────────────────────────────────────────┘    │
│                        UNTRUSTED BOUNDARY                         │
└───────────────────────────────────────────────────────────────────┘
```

**Trust boundary rules:**
1. Everything inside the application boundary is trusted. Everything outside is untrusted.
2. Platform secure storage is a trusted boundary extension — we delegate key storage to the OS.
3. External transports carry ciphertext only. Trusted for delivery, not confidentiality.
4. The optional sync server is trusted for availability and conflict resolution only. Never trusted for confidentiality.
5. User input enters the trust boundary at the application layer and is immediately consumed for key derivation — never persisted.

---

## 5. Cryptographic Architecture

### 5.1 Primitive Selection

#### Symmetric Encryption: XChaCha20-Poly1305 (RFC 8439)

**Selected over AES-256-GCM because:**

1. **Nonce management.** XChaCha20 uses 192-bit nonces, making random nonce generation safe without collision concerns. AES-GCM requires careful nonce management (96-bit, unique per key). A 96-bit nonce space with random generation reaches birthday bound at ~2^48 encryptions — feasible in a long-lived vault. XChaCha20's 192-bit nonce eliminates this concern entirely.

2. **Software performance.** ChaCha20 is faster than AES on devices without AES-NI. Even with ARM Crypto Extensions on modern SoCs, ChaCha20-Poly1305 is competitive.

3. **Consistent performance.** AES-GCM performance varies dramatically across platforms (hardware-accelerated on some, pure software on others). XChaCha20-Poly1305 delivers consistent performance everywhere.

4. **Side-channel resistance.** ChaCha20 is inherently more resistant to timing side-channels than table-based AES implementations. ChaCha20's constant-time arithmetic is simpler to verify.

**AES-256-GCM is still used internally** for hardware-backed key wrapping in Android Keystore / iOS Secure Enclave (these hardware modules only support AES operations internally). Our application code never handles the raw AES key in these cases.

#### Key Derivation: Argon2id (RFC 9106)

**Selected over PBKDF2 and scrypt because:**

1. **Modern standard.** RFC 9106 (June 2023) formalizes Argon2 as the IETF-recommended password hashing function. Argon2id won the Password Hashing Competition (2015).

2. **Memory-hard.** Argon2id's memory cost parameter makes parallelized brute-force attacks (GPU, ASIC, FPGA) economically infeasible. PBKDF2 with SHA-256 requires minimal memory, making it highly parallelizable.

3. **Tunable parameters.** Independent control over time cost, memory cost, and parallelism allows optimization for mobile vs desktop.

4. **Resistance to side-channel attacks.** Argon2id's hybrid construction provides resistance to both side-channel and time-memory tradeoff attacks.

5. **Widely implemented.** Available in libsodium, Argon2 reference implementation, and platform-native implementations across all target platforms.

**Parameters:**
```
Type:     Argon2id
Version:  0x13 (latest)
Salt:     16 bytes, cryptographically random (per vault)
Memory:   128 MiB (desktop), 64 MiB (mobile, configurable)
Time:     3 (iterations)
Parallelism: 4 (desktop), 2 (mobile)
Output:   32 bytes (256 bits)
```

**OWASP alignment:** The OWASP Password Storage Cheat Sheet (2024) recommends Argon2id with minimum 128 MiB memory, minimum 2 iterations, and minimum parallelism of 1. Our parameters meet or exceed these on desktop, and slightly below on mobile (64 MiB) — compensated by the Device Unlock Key mechanism.

#### Key Wrapping: HMAC-SHA256 + AES-256-GCM

**Selected for authenticated wrapping of keys.** HMAC-SHA256 is well-analyzed, hardware-accelerated on all target platforms, and provides the necessary authentication guarantee. We wrap DEKs using a key derived from the VEK via HMAC-SHA256, then encrypt with AES-256-GCM.

#### Signatures: Ed25519 (RFC 8032)

**Selected for sharing package authentication.** 64-byte signatures, 32-byte public keys, deterministic signatures (no per-signature randomness), fast verification. Available in libsodium, BouncyCastle, and platform libraries.

#### Key Agreement: X25519 (RFC 7748)

**Selected for sharing key exchange.** 32-byte keys, fast scalar multiplication, co-designed with Ed25519, resistant to timing attacks.

#### Random Number Generation

- **Android:** `java.security.SecureRandom` (seeded from `/dev/urandom`). Native: `libsodium randombytes_buf()`.
- **Desktop:** OS CSPRNG (`CryptGenRandom` on Windows, `/dev/urandom` on Linux, `SecRandomCopyBytes` on macOS).
- **Never:** `java.util.Random`, `Math.random()`, `rand()`, or any non-cryptographic PRNG.

### 5.2 Cryptographic Parameters Summary

| Primitive | Algorithm | Key/Output Size | Parameters |
|---|---|---|---|
| Master key derivation | Argon2id | 32 bytes | m=128MiB/64MiB, t=3, p=4/2 |
| Record encryption | XChaCha20-Poly1305 | 32-byte key | 192-bit nonce, 128-bit tag |
| Key wrapping | HMAC-SHA256 + AES-256-GCM | 32-byte keys | 96-bit nonce, counter-based |
| Digital signatures | Ed25519 | 32B key, 64B sig | RFC 8032 |
| Key agreement | X25519 | 32-byte keys | RFC 7748 |
| Secure random | OS CSPRNG | N/A | Platform-native |

### 5.3 Authenticated Encryption Properties

Every encrypted record produces `(nonce, ciphertext, authentication_tag)`.

XChaCha20-Poly1305 provides:
- **Confidentiality:** Ciphertext reveals no information about plaintext without the key.
- **Authenticity:** Any modification to ciphertext, nonce, or associated data causes verification failure.
- **Associated Data (AAD):** We bind ciphertext to record metadata (type, version, record ID) to prevent record type confusion attacks.

**Critical rule:** Decryption failure MUST abort the entire vault unlock. A single corrupted or tampered record must halt the process and alert the user.

---

## 6. Key Hierarchy

```
┌──────────────────────────────────────────────────────────────────────┐
│                      COMPLETE KEY HIERARCHY                           │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Master Password (human-remembered)                         │      │
│  │  NEVER STORED. Only exists during unlock.                   │      │
│  └────────────────────┬───────────────────────────────────────┘      │
│                       │ Argon2id(password, salt, params)             │
│                       ▼                                               │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Key Encryption Key (KEK) ─── 32 bytes                     │      │
│  │  Derived from master password. NOT stored.                  │      │
│  │  Exists only in RAM during unlock.                          │      │
│  └────────────────────┬───────────────────────────────────────┘      │
│                       │ encrypts/decrypts                            │
│                       ▼                                               │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Vault Encryption Key (VEK) ─── 32 bytes                   │      │
│  │  Randomly generated. Stored encrypted under KEK.            │      │
│  │  Decrypts entire vault payload.                             │      │
│  └────────────────────┬───────────────────────────────────────┘      │
│                       │ encrypts/decrypts                            │
│                       ▼                                               │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Vault Payload                                              │      │
│  │  Contains:                                                  │      │
│  │  - Per-record Data Encryption Keys (DEKs)                   │      │
│  │  - Encrypted record blobs                                   │      │
│  │  - Encrypted metadata                                       │      │
│  └────────────────────────────────────────────────────────────┘      │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Per-Record Data Encryption Key (DEK) ── 32 bytes          │      │
│  │  Random per record. Stored encrypted under VEK.             │      │
│  │  Encrypts one record's plaintext.                           │      │
│  │  Allows individual record re-encryption.                    │      │
│  └────────────────────┬───────────────────────────────────────┘      │
│                       │ encrypts                                      │
│                       ▼                                               │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Record Ciphertext ─ XChaCha20-Poly1305                    │      │
│  │  (nonce, encrypted_data, tag)                               │      │
│  └────────────────────────────────────────────────────────────┘      │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Device Unlock Key (DUK)                                   │      │
│  │  Hardware-backed (Keystore/SE/TPM). Non-exportable.         │      │
│  │  Wraps cached KEK for fast biometric unlock.                │      │
│  └────────────────────┬───────────────────────────────────────┘      │
│                       │ authorizes                                    │
│                       ▼                                               │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Wrapped KEK Cache                                          │      │
│  │  KEK encrypted under DUK. Stored in app private storage.    │      │
│  │  Avoids Argon2id on every unlock.                           │      │
│  └────────────────────────────────────────────────────────────┘      │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Device Pairing Key (DPK) ─ Ed25519 key pair               │      │
│  │  Private key in hardware keystore. Used for pairing auth.   │      │
│  └────────────────────────────────────────────────────────────┘      │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Sharing Identity Key (SIK)                                │      │
│  │  X25519 + Ed25519 key pairs for sharing.                    │      │
│  │  Private keys in hardware keystore.                         │      │
│  └────────────────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────────────┘
```

### 6.1 Key-by-Key Analysis

#### KEK (Key Encryption Key)

| Property | Value |
|---|---|
| **Creator** | Application, during vault creation or master password change |
| **Generation** | Argon2id(master_password, vault_salt, parameters) |
| **Size** | 32 bytes |
| **Persistence** | Never directly persisted. Re-derivable from master password. Optionally cached encrypted under DUK. |
| **Protection** | Requires master password to derive. If DUK cache is used, additionally gated by biometrics/device credential. |
| **Compromise impact** | Full vault access. Attacker can decrypt VEK and all records. |
| **Rotation** | Re-derived on master password change. |

**Key insight:** The KEK is never stored. It can always be re-derived. There is no KEK to steal. The only attack vector is online/offline brute-force of the master password — mitigated by Argon2id parameters.

#### VEK (Vault Encryption Key)

| Property | Value |
|---|---|
| **Creator** | Application, during vault creation |
| **Generation** | CSPRNG (32 random bytes) |
| **Size** | 32 bytes |
| **Persistence** | Stored encrypted under KEK. Never in plaintext on disk. |
| **Protection** | Encrypted by KEK. KEK requires master password. |
| **Compromise impact** | Full vault access (but attacker still needs KEK to decrypt VEK). |
| **Rotation** | Triggered by master password change. Old VEK decrypted with old KEK, re-encrypted with new KEK. |

**Key insight:** The VEK is a randomly generated key. Its security is entirely dependent on the KEK protecting it.

#### DEK (Data Encryption Key)

| Property | Value |
|---|---|
| **Creator** | Application, during record creation |
| **Generation** | CSPRNG (32 random bytes per record) |
| **Size** | 32 bytes |
| **Persistence** | Stored encrypted under VEK, bundled with each record. |
| **Protection** | Encrypted by VEK → encrypted by KEK → requires master password. |
| **Compromise impact** | Single record compromised only. |
| **Rotation** | Per-record re-encryption when record is modified. |

**Key insight:** Per-record DEKs enable granular key rotation. When VEK is rotated, all DEK wrappers are re-encrypted. Individual record plaintexts remain encrypted under their DEKs.

#### Device Unlock Key (DUK)

| Property | Value |
|---|---|
| **Creator** | Platform Keystore/Keychain |
| **Generation** | Hardware or OS-generated asymmetric key pair. Private key non-exportable. |
| **Persistence** | Private key in hardware secure element. Cannot be extracted. |
| **Protection** | Hardware-backed. Biometric/device credential gated for use. |
| **Compromise impact** | Allows biometric unlock without master password. Does not compromise vault keys directly. |
| **Rotation** | Application generates new wrapped KEK when DUK changes. |

**Key insight:** The DUK never protects secrets directly. It only wraps a cached copy of the KEK. If the DUK is lost (device replaced), the user enters their master password to re-derive the KEK. Biometric unlock is a **convenience feature**, not a security boundary.

#### Device Pairing Key (DPK)

| Property | Value |
|---|---|
| **Creator** | Application, during device pairing |
| **Generation** | Ed25519 key pair |
| **Persistence** | Private key in hardware keystore. |
| **Compromise impact** | Could impersonate paired device. Vault keys NOT at risk. |
| **Rotation** | New pairing generates new key pair. Old pairings can be revoked. |

#### Sharing Identity Key (SIK)

| Property | Value |
|---|---|
| **Creator** | Application, during first share |
| **Generation** | X25519 + Ed25519 key pairs |
| **Persistence** | Private keys in hardware keystore. |
| **Compromise impact** | Could impersonate user for share creation. Full vault NOT at risk. |
| **Rotation** | User-initiated. Old SIK public key published as revoked. |

---

## 7. Key Lifecycle

### 7.1 Vault Creation

```
1. User chooses master password
2. Generate 16-byte random salt (vault_salt)
3. Generate 32-byte random VEK
4. KEK = Argon2id(master_password, vault_salt, m=128MiB, t=3, p=4)
5. wrapped_vek = AES-256-GCM_Encrypt(KEK, nonce, VEK, AAD=vault_metadata)
6. vault_file = { version, algorithm_ids, vault_salt, kdf_parameters, wrapped_vek, encrypted_vault_payload }
7. Zeroize KEK from memory
8. Store vault_file in application private storage
```

### 7.2 Vault Unlock

```
1. Read vault_file from storage
2. Prompt user for master password
3. KEK = Argon2id(master_password, vault_salt, m=128MiB, t=3, p=4)
4. VEK = AES-256-GCM_Decrypt(KEK, nonce, wrapped_vek, tag, AAD=vault_metadata)
5. If decryption fails → WRONG PASSWORD (abort)
6. If decryption succeeds → VEK is now in RAM
7. Decrypt vault_payload with VEK
8. Load records into decrypted in-memory cache
9. Zeroize KEK from memory (VEK remains for session)
```

### 7.3 Vault Lock

```
1. Zeroize all plaintext records from memory
2. Zeroize VEK from memory
3. Clear all cached plaintext
4. Invalidate any cached KEK wrap
5. Lock UI — require re-authentication
6. Revoke any in-flight biometric auth tokens
```

### 7.4 Master Password Change

```
1. User provides old master password + new master password
2. Derive old_KEK = Argon2id(old_password, vault_salt, m=128MiB, t=3, p=4)
3. Decrypt VEK with old_KEK
4. Generate new vault_salt (16 bytes random)
5. Derive new_KEK = Argon2id(new_password, new_salt, m=128MiB, t=3, p=4)
6. Re-encrypt VEK with new_KEK
7. Store new vault_salt + new wrapped VEK
8. DEKs remain encrypted under VEK (no re-encryption needed)
9. Zeroize old_KEK and old password strings from memory
```

**Why individual record plaintexts don't need re-encryption:** Records are encrypted with per-record DEKs. DEKs are encrypted under the VEK. Changing the master password changes the KEK (which wraps the VEK), which wraps all DEK metadata. Individual record plaintexts remain encrypted under their DEKs — which are still valid.

### 7.5 Key Destruction

Keys are destroyed by:
1. **Secure memory zeroization:** Overwrite memory with zeros then random bytes. In managed runtimes, use mutable byte buffers and explicitly zero them. In Rust, use `zeroize` crate.
2. **Memory locking:** On desktop, use `mlock()` to prevent swapping to disk while keys are in RAM.
3. **Garbage collection awareness:** Explicitly zero byte arrays before dereferencing. Do NOT rely on GC.
4. **Platform secure element deletion:** Set key validity to session-based or use `destroyKey()`.

### 7.6 Lost Device

1. User acquires new device.
2. User enters master password on new device → derives KEK → decrypts VEK.
3. If user has encrypted backup: import backup, verify master password.
4. If user has recovery phrase: use phrase to derive KEK.
5. **Without any recovery material:** vault is unrecoverable. This is the honest cost of zero-knowledge.

### 7.7 Compromised Device

1. User detects device compromise.
2. User changes master password on a SAFE device.
3. New KEK + new VEK generated.
4. All records re-encrypted under new keys.
5. Old vault file cryptographically destroyed (overwrite with random data).
6. Paired devices revoked — attacker may have extracted pairing keys.
7. Recovery phrase regenerated.

---

## 8. Master Password & Authentication

### 8.1 Argon2id Parameters

```
Function:   Argon2id
Version:    0x13 (latest)
Type:       Argon2id (mode 2 = hybrid: first pass Argon2i, rest Argon2d)
Salt:       16 bytes, cryptographically random, unique per vault
Memory:     128 MiB (desktop), 64 MiB (mobile, configurable)
Time cost:  3 iterations
Parallelism: 4 lanes (desktop), 2 lanes (mobile)
Output:     32 bytes (256 bits)
```

**Parameter rationale:**

| Parameter | Desktop | Mobile | Rationale |
|---|---|---|---|
| Memory | 128 MiB | 64 MiB | Desktop can afford 128 MiB. Mobile limited by RAM but 64 MiB feasible. |
| Time | 3 | 3 | ~1-2 seconds on modern hardware. |
| Parallelism | 4 | 2 | Matches available CPU cores. |
| Salt | 16 bytes | 16 bytes | 2^128 possible salts. Prevents precomputation. |

**Mobile adaptation:** Detect device class at vault creation. Offer presets: "Standard" (64 MiB, 2 iters), "High" (128 MiB, 3 iters), "Custom." On low-RAM devices (<4 GB), default to standard. On high-RAM devices (>8 GB), default to high.

### 8.2 Offline Password Guessing

```
Attacker obtains: encrypted vault file
Attacker can:
1. Read vault header: salt (16B), Argon2id params, wrapped VEK, nonce, tag
2. For each password guess:
   a. KEK = Argon2id(guess, salt, m, t, p)
   b. VEK = AES-GCM_Decrypt(KEK, nonce, wrapped_vek, tag, AAD)
   c. If tag fails → try next guess
   d. If tag succeeds → have KEK and VEK → full vault access
```

**Protection:** Argon2id memory hardness limits GPU parallelism. A 6-word Diceware passphrase (~78 bits) provides ~600 years of attack time at ~10,000-50,000 guesses/second on a modern GPU.

### 8.3 Honest Assessment

An attacker with a modern GPU can attempt ~10,000-50,000 passwords/second. A strong master password with 60+ bits of entropy provides ~2 years of attack time. A 6-word Diceware passphrase (~78 bits) provides ~600 years. These are practical security levels.

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

## 11. Metadata Privacy

### 11.1 Threat Assessment

| Data Point | Leakage | Attack Value | Mitigation |
|---|---|---|---|
| Number of records | Record count | Determines if target is high-value | Minimal — accept |
| Record types | Plaintext in directory |  targeting | Low risk |
| Record sizes | Encrypted size | Infers secret types | Low risk |
| Timestamps | Now encrypted | Activity patterns | Encrypted |
| Folder structure | Part of record data | Organizational structure | Encrypted |
| Record names | Now encrypted |  | Encrypted |

### 11.2 Recommended Protections

1. **Encrypt timestamps.** Store creation/modification times encrypted under the DEK.
2. **Encrypt record names and folder names.** These are part of the record plaintext.
3. **Accept record type leakage.** Needed for UI icon/format display. Coarse categories limit information value.
4. **Accept record count leakage.** Hiding requires dummy records — significant complexity for marginal benefit.

---

## 12. Android Security Architecture

### 12.1 Android Keystore & StrongBox

**Android Keystore** is the platform's secure key storage. Keys stored in the Keystore:
- Cannot be extracted (private key material never leaves secure hardware).
- Can be hardware-backed (TEE or StrongBox).
- Can be gated by biometric authentication.
- Can be bound to specific authentication validity periods.

**StrongBox** (Android 9+, required on Android 14+ for biometric-bound keys):
- Dedicated secure element (hardware security module on-die).
- Independent CPU, RAM, and secure storage.
- FIPS 140-2 Level 3 certified.
- Available on most modern devices (Pixel 3+, Samsung S10+, etc.).

**Fallback:** TEE-backed Keystore keys. Software-backed keys (last resort — warn user). Use `KeyInfo.isInsideSecureHardware()` to check.

### 12.2 Biometric Integration

```kotlin
val keyGen = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
)
val keySpec = KeyGenParameterSpec.Builder("device_unlock_key",
    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationValidityDurationSeconds(30)
    .setStrongBoxBacked(true)
    .build()
keyGen.init(keySpec)
keyGen.generateKey()
```

### 12.3 Security Controls

| Control | Implementation | Security Effect |
|---|---|---|
| **FLAG_SECURE** | `window.setFlags(FLAG_SECURE, FLAG_SECURE)` | Prevents screenshots, screen recording, recent-apps preview |
| **Clipboard protection** | Auto-clear on vault lock; warn before copy | Prevents clipboard persistence |
| **Autofill service** | Implement `AutofillService` with domain verification | Secure autofill |
| **Notification privacy** | `setVisibility(Notification.VISIBILITY_SECRET)` | No content in lock screen notifications |
| **App lock timeout** | Auto-lock after configurable period (default 5 min) | Limits window of opportunity |
| **Root detection** | Check su binary, Magisk, dangerous props | Warn user, disable biometric unlock |
| **Debugger detection** | `Debug.isDebuggerConnected()` | Warn or disable features |
| **APK integrity** | Verify signing certificate at runtime | Detect tampered APK |
| **Backup exclusion** | `android:allowBackup="false"` | Prevents adb backup |
| **Play App Signing** | Google Play App Signing | Google manages signing key |

### 12.4 Rooted Device Behavior

```
If rooted:
├── WARN user prominently on first launch
├── DISABLE biometric unlock
├── DISABLE Device Unlock Key caching
├── REQUIRE master password for every unlock
├── INCREASE Argon2id parameters (if user consents)
├── BLOCK backup/sync features
└── LOG detection (local only, not transmitted)
```

**Honest assessment:** Root detection is inherently a cat-and-mouse game. Magisk Hide, KernelSU, and zygisk can hide root. A determined attacker on a rooted device can read application private storage, capture screen content, intercept touch input, and dump process memory.

**Mitigation:** Use hardware-backed Keystore keys (persist even if OS compromised), require master password for unlock, minimize plaintext lifetime in memory.

### 12.5 Android Backup

- `android:allowBackup="false"` prevents Android Auto Backup and adb backup.
- Our own encrypted backup: user-initiated, encrypted with separate password.

---

## 13. Desktop Security Architecture

### 13.1 Windows

**DPAPI:** `CryptProtectData()` / `CryptUnprotectData()`. Keys derived from user's logon credentials + machine-specific secret. Useful for caching KEK. TPM can provide additional binding.

**Windows Hello:** Biometric or PIN authentication. Underlying credential stored in TPM. Uses CNG key storage providers.

**TPM:** Hardware security chip. Can generate and store keys that cannot be extracted. Supports key attestation and key sealing to PCR values.

### 13.2 macOS

**Keychain:** System keychain for small secrets. Items tagged with access control (require user presence, Touch ID). Encrypted with keys derived from user's login password.

**Secure Enclave:** Dedicated security coprocessor. Generates and stores asymmetric keys. Private keys never leave Secure Enclave. Touch ID handled within SE.

```swift
let tag = "com.yourapp.device-unlock-key".data(using: .utf8)!
let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs as String: [
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: tag,
        kSecAttrAccessControl as String: SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .biometryAny, nil
        )!
    ]
]
```

**App Sandbox:** Entitlements control access. Hardened runtime enabled. Library validation enforced.

### 13.3 Linux

**Secret Service API:** D-Bus-based secret storage (GNOME Keyring, KDE KWallet). Encrypted, unlocked at user login.

**TPM 2.0:** Available on most modern laptops. `tpm2-tools` for interaction.

**Filesystem encryption:** LUKS/dm-crypt for full-disk, eCryptfs for home directory.

### 13.4 Cross-Platform Desktop Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Platform Detection Layer                                    │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────┐  │
│  │ Windows  │  │  macOS   │  │  Linux   │  │   Other    │  │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └─────┬──────┘  │
│       │              │              │                │        │
│       ▼              ▼              ▼                ▼        │
│  ┌──────────────────────────────────────────────────────┐    │
│  │            Unified Key Management API                │    │
│  └──────────────────────────────────────────────────────┘    │
│  Used for: cached KEK wrapping, DUK, sharing keys, pairing   │
│  Implementation: Rust + platform-specific crates             │
└──────────────────────────────────────────────────────────────┘
```

**Recommendation:** Use Rust for the cross-platform crypto/storage layer. Platform crates: `rust-windows` for Windows APIs, `security-framework` for macOS, `zbus` + `tpm2` for Linux.

---

## 14. Biometric Authentication

### 14.1 Design Principle

**Biometric authentication is a convenience gating mechanism. It is NOT the vault encryption key.**

Biometric templates are:
- Not secrets (fingerprint/face is left everywhere).
- Not consistent (fingerprints change, face ages).
- Not revocable (cannot get a new fingerprint).

### 14.2 Correct Biometric Flow

```
Step 1: User touches fingerprint / looks at face
Step 2: OS Secure Hardware validates biometric (TEE / Secure Enclave)
Step 3: TEE/SE authorizes use of hardware-backed private key
Step 4: Application receives authorization token / key use
Step 5: Application decrypts cached KEK using DUK
Step 6: Application decrypts VEK from cached KEK
Step 7: Vault is unlocked. Session begins.

What biometrics UNLOCK:
✓ A cached, KEK-encrypted key wrapper
✗ The master password
✗ The VEK directly
✗ The vault encryption process
```

### 14.3 Why Not Direct Biometric Keys?

**Hypothetical (DO NOT implement):** Use biometric template hash as KEK.
- Fingerprint changes → KEK changes → vault inaccessible.
- Biometric data is not secret → anyone with fingerprint can derive KEK.
- No revocation possible.

### 14.4 Biometric Change Handling

| Event | Action |
|---|---|
| Fingerprint added | No action (additional fingerprint) |
| Fingerprint removed | No action (remaining fingerprints work) |
| All fingerprints removed | Biometric unlock disabled. Master password still works. |
| Face data reset | Biometric unlock disabled. Master password still works. |

### 14.5 Hardware-Backed vs Software-Backed

| Scenario | Behavior |
|---|---|
| StrongBox / Secure Enclave | Hardware-backed DUK. Biometric unlock enabled. |
| TEE only | TEE-backed DUK. Biometric enabled with warning. |
| Software-backed only | Disable biometric unlock. Master password only. Warn user. |
| Rooted / compromised TEE | Disable biometric unlock. Master password only. |

---

## 15. No-Server Secret Sharing Protocol

### 15.1 Protocol: X25519 + Ed25519 Envelope

```
SENDER
1. Load recipient's public key
2. Generate ephemeral X25519 key pair (eph_priv, eph_pub)
3. shared_secret = X25519(eph_priv, recipient_pub_x)
4. enc_key = HKDF-SHA256(shared_secret, salt=eph_pub||recipient_pub_x, info="share-v1-enc")
5. ciphertext = XChaCha20-Poly1305_Encrypt(enc_key, nonce, plaintext)
6. signature = Ed25519_Sign(sender_priv, package_contents)
7. Assemble package: { version, eph_pub, recipient_pub_x, sender_pub_x, ciphertext, nonce, signature, expiry, one_time, package_id }
8. Transmit via WhatsApp/email/QR/etc.

RECIPIENT
1. Receive package
2. Verify recipient_pub_x matches own key (reject if not)
3. Verify Ed25519 signature (reject if invalid)
4. Check expiry (reject if expired)
5. Check one_time flag (reject if already used)
6. shared_secret = X25519(recipient_priv, eph_pub)
7. enc_key = HKDF-SHA256(shared_secret, salt=eph_pub||recipient_pub_x, info="share-v1-enc")
8. plaintext = XChaCha20-Poly1305_Decrypt(enc_key, nonce, ciphertext)
9. Present to user / store in vault
```

### 15.2 Package Format

```
Share Package (version 1) — 256 bytes fixed for small secrets:
┌─────────────────────────────────────────────────────────────────┐
│ Bytes  │ Field           │ Type      │ Description             │
├─────────────────────────────────────────────────────────────────┤
│ 0-3    │ magic           │ uint32    │ 0x53485231 ("SHR1")    │
│ 4      │ version         │ uint8     │ Protocol version        │
│ 5      │ flags           │ uint8     │ Bitfield (expiry, etc.) │
│ 6-7    │ reserved        │ uint16    │ Future use              │
│ 8-15   │ package_id      │ uint64    │ Random ID (replay)      │
│ 16-19  │ created_at      │ uint32    │ Unix timestamp          │
│ 20-23  │ expires_at      │ uint32    │ Unix timestamp (0=∞)    │
│ 24-55  │ sender_pub_x    │ 32 bytes  │ Sender X25519 pubkey    │
│ 56-87  │ recipient_pub_x │ 32 bytes  │ Recipient X25519 pub    │
│ 88-119 │ eph_pub         │ 32 bytes  │ Ephemeral X25519 pub    │
│ 120-183│ ciphertext      │ 64 bytes  │ Encrypted secret        │
│ 184-199│ nonce           │ 16 bytes  │ XChaCha20 nonce         │
│ 200-247│ nonce           │ 16 bytes  │ XChaCha20 nonce         │
│ 248-311│ signature       │ 64 bytes  │ Ed25519 signature       │
│ 312-319│ aad_hash        │ 8 bytes   │ BLAKE3 of AAD fields    │
└─────────────────────────────────────────────────────────────────┘
```

### 15.3 Security Properties

| Property | How Achieved |
|---|---|
| Confidentiality | X25519 ECDH + HKDF-derived AES key |
| Sender authentication | Ed25519 signature |
| Recipient binding | X25519 shared secret requires recipient's private key |
| Forward secrecy | Ephemeral key pair per share |
| Replay protection | Random package_id |
| Key confirmation | AAD hash verified during decryption |
| Expiry | Timestamp in package |
| One-time use | Flag + recipient-side tracking |

### 15.4 QR Code Pairing for Sharing

QR code contains: sender's X25519 + Ed25519 public keys, display name, one-time code for MITM detection. Recipient scans, verifies display name matches expected sender (out-of-band), sends response QR with their public keys.

---

## 16. WhatsApp as Transport Layer

### 16.1 Security Boundary

**What WhatsApp CAN see:**
- Ciphertext (encrypted package bytes)
- Sender/recipient phone numbers
- Timestamp of message
- Delivery status

**What WhatsApp CANNOT see:**
- Plaintext secret
- Master password
- Vault key
- Sharing private key
- Shared secret (ECDH result)

**What WhatsApp provides:**
- Transport encryption (Signal Protocol)
- Delivery confirmation

**What WhatsApp does NOT provide (we handle):**
- Application-level plaintext protection
- Sender authentication (we provide Ed25519)
- Recipient authentication (we provide X25519 binding)
- Forward secrecy for sharing (we provide ephemeral keys)
- Replay protection (we provide package_id)
- Expiry enforcement (we provide timestamp)

### 16.2 WhatsApp-Specific Risks

| Risk | Severity | Mitigation |
|---|---|---|
| WhatsApp backups | Medium | Package already encrypted. Backup stores ciphertext only. |
| Message forwarding | Low | Recipient verifies sender identity regardless. |
| Screenshots | Medium | Recipient-side risk, not transport. |
| Notification previews | Low-Medium | Ciphertext in preview has no readable content. |
| Linked devices | Medium | Compromised linked device sees ciphertext only. |
| Compromised recipient device | High | Cannot protect against this. |

### 16.3 Transport Comparison

| Transport | Confidentiality | Practicality | Notes |
|---|---|---|---|
| WhatsApp | Good | Excellent | Ubiquitous. E2E transport + our encryption. |
| Signal | Better | Good | No cloud backup by default. Less widely used. |
| Email | Poor | High | Not E2E at transport. Avoid for sensitive shares. |
| SMS | Poor | High | SS7 not encrypted. Avoid entirely. |
| QR code | Excellent | Good | Physical proximity. Best for same-room. |
| NFC | Excellent | Limited range | Best for device-to-device. |
| Bluetooth | Good | Medium range | Good for local sharing. |

**Recommendation:** WhatsApp is acceptable. Our application-level encryption is independent of transport encryption. Even if WhatsApp's encryption fails, the share package is protected by X25519 + AES.

**Honest limitations:** Cannot prevent recipient's device being compromised, recipient taking screenshots, or recipient forwarding plaintext after decryption.

---

## 17. Device-to-Device Pairing

### 17.1 Protocol

```
DEVICE A (initiator)                  DEVICE B (responder)
1. Generate pairing ID (random 8-digit)
2. Generate Ed25519 key pair (DPK_A)
3. Display pairing code [A][B][C][D] ──────────────▶
                                              4. User confirms pairing code
5. Generate DPK_B, sign both DPKs ◀────────────── 6. Sign response with device key
7. User confirms pairing on A
8. Verify B's signature
9. Store B's DPK_B
10. Send A's DPK_A (signed) ─────────────────────▶
                                             11. Verify A's signature
                                             12. Store DPK_A
13. Paired!                                    14. Paired!
```

### 17.2 Human Verification

The 8-digit code displayed on both devices simultaneously. User compares visually or verbally. If codes match → MITM excluded. If codes don't match → abort. Same method used by Signal.

### 17.3 Post-Pairing

Paired devices can exchange encrypted vault sync packages, send encrypted secrets directly. Any device can revoke others. Revoked devices cannot decrypt future packages.

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

## 19. Backup & Recovery

### 19.1 Recovery Options

#### Option A: Recovery Phrase (Recommended)

- 24-word mnemonic (256 bits entropy, BIP-39-style).
- Shown ONCE during setup. User must acknowledge.
- Written down, stored offline.
- Equivalent security to master password.
- Recovery: enter phrase → Argon2id → KEK → VEK → vault recovered.

#### Option B: Shamir Secret Sharing

- Split KEK recovery material into N shares (e.g., 3 of 5).
- M-1 shares provide zero information.
- Pros: No single point of failure.
- Cons: Complex UX. User must manage trusted contacts.

#### Option C: Recovery Key File

- 256-bit random recovery key encrypted with user-provided password.
- User downloads and stores separately from vault.
- Simple. No memorization required.
- Cons: File can be lost, stolen, or damaged.

### 19.2 Recommended Architecture

All three options provided, user chooses:
1. Master password (primary)
2. Recovery phrase (backup) — shown once, user confirms recording
3. Recovery key file (alternative)

**What we CANNOT do:**
- Recover vault if ALL recovery material is lost
- Provide a backdoor recovery mechanism
- Send the user's master password via email

This is the honest cost of zero-knowledge.

---

## 20. Password Generator

### 20.1 Design

**Modes:**
1. **Random:** charset = user-selected groups. Entropy = L × log2(N).
2. **Passphrase:** 7776-word Diceware list. 6 words → 77.5 bits entropy.
3. **PIN:** Digits only. Entropy = 3.32 × L.
4. **Pronounceable:** Markov chain generation.

**Character groups (user toggles):**
- Uppercase (26), Lowercase (26), Digits (10), Symbols (32), Custom

**Minimum recommendations:**
- Random: 16+ chars, ≥80 bits entropy
- Passphrase: 6+ words, ≥77 bits entropy
- PIN: 6+ digits (low security only)

**CSPRNG:** Platform-native OS CSPRNG only. Never `Math.random()` or equivalents.

---

## 21. TOTP / 2FA

### 21.1 Implementation

- TOTP secret stored encrypted with record's DEK.
- Generation: HMAC-SHA1(secret, floor(unix_time/30)) → 6/8 digit code.
- Display: code with countdown timer, auto-refresh, auto-clear after inactivity.
- Import: parse `otpauth://` URI, extract secret/issuer/account/algorithm.
- QR scanning: camera or image-based QR scanner.

---

## 22. Autofill Architecture

### 22.1 Android Autofill

```kotlin
class SecretManagerAutofillService : AutofillService() {
    override fun onFillRequest(request: FillRequest, callback: FillResponseCallback) {
        // 1. Get autofill field context
        // 2. Verify domain matches saved URL
        // 3. Present credentials to user for selection
        // 4. Fill response with credential data
    }
}
```

**Security controls:**
1. **Domain verification:** Match requesting app's domain against stored URLs. Mismatch → warn.
2. **User confirmation:** Never silently autofill.
3. **Save prompt:** Prompt user to save new credentials with preview.
4. **Category filtering:** Only autofill passwords on login forms, credit cards on payment forms.

### 22.2 Desktop Autofill

- Manifest V3 browser extension (Chrome/Firefox/Edge).
- Native Messaging Host communicates with desktop app.
- Desktop app decrypts credentials, sends to extension.
- Extension injects into page.

### 22.3 Anti-Phishing

| Attack | Protection |
|---|---|
| Domain mismatch | Compare against stored URL. Mismatch → warn. |
| Subdomain attack | `evil.example.com` vs `example.com` → different domains |
| IDN/punycode | Convert IDN to Unicode. Detect homoglyphs. |
| Deceptive URLs | Warn on unexpected TLD or suspicious patterns. |
| HTTP sites | Warn when autofilling on non-HTTPS. |

---

## 23. Memory Security

### 23.1 Plaintext Lifetime

| Phase | Plaintext in Memory | Duration |
|---|---|---|
| Vault unlocked | VEK + decrypted records | Entire session |
| Record viewed | Individual record | While viewing |
| TOTP displayed | TOTP code | ~5 seconds |
| Search | Decrypted fields | During search |

### 23.2 Zeroization

**Rust:**
```rust
use zeroize::Zeroize;
struct SecretBuffer { data: [u8; 32] }
impl Drop for SecretBuffer {
    fn drop(&mut self) { self.data.zeroize(); }
}
```

**Kotlin:**
```kotlin
class SecureByteArray(private val size: Int) {
    private val data = ByteArray(size)
    fun clear() { Arrays.fill(data, 0.toByte()) }
}
```

### 23.3 What We CANNOT Control

| Threat | Platform | Mitigation |
|---|---|---|
| Garbage collection | JVM | Explicitly zero byte arrays before dereferencing |
| Swap/page file | Desktop | `mlock()` / `VirtualLock()` |
| Core dumps | Linux | Disable core dumps (`ulimit -c 0`) |
| Crash dumps | All | Configure crash reporters to exclude app data |
| Debugging | All | Detect debugger attachment |
| Memory forensics | All | Minimize plaintext lifetime. Cannot fully prevent. |
| JIT compilation | JVM | Interpreter mode for crypto-critical paths |
| Copy-on-write | All | OS-level. Cannot prevent. |

**Honest assessment:** Complete memory security is impossible on modern operating systems. We minimize plaintext lifetime, use secure buffers with zeroization, lock sensitive pages, and use Rust for crypto-critical code. We cannot prevent kernel exploits, DMA attacks, cold boot attacks, or debugging by privileged attackers.

---

## 24. Clipboard Security

| Feature | Implementation |
|---|---|
| Auto-clear | Clear after configurable timeout (default: 30s) |
| Manual clear | "Clear clipboard" button |
| Copy warning | User confirms before copying sensitive values |
| No auto-copy | Never automatically copy to clipboard |
| Format | Plain text only |

---

## 25. Secure UI

| Control | Implementation |
|---|---|
| Secret masking | `••••••` by default |
| Reveal timeout | Auto-mask after N seconds (default: 5s) |
| Re-authentication | Biometric/master password for sensitive records |
| Screenshot blocking | FLAG_SECURE (Android), platform equivalents |
| Notification privacy | No secret content in notifications |
| Recent-apps preview | FLAG_SECURE prevents preview |
| Copy buttons | Explicit copy with confirmation |
| Destructive actions | Confirmation dialog + re-auth |
| Lock behavior | Auto-lock after configurable timeout (default: 5 min) |

---

## 26. Security Levels

### Level 1: Basic (Default)
- Master password unlocks vault.
- KEK cache for fast unlock.
- Auto-lock after 5 minutes.
- Standard Argon2id parameters.
- **Protects against:** Stolen locked device, stolen vault file.

### Level 2: Enhanced
- Biometric unlock enabled.
- DUK caches KEK for biometric unlock.
- Auto-lock after 2 minutes.
- Above-standard Argon2id.
- FLAG_SECURE, clipboard auto-clear.
- **Protects against:** Level 1 + shoulder surfing, screenshots.

### Level 3: High Security
- Biometric + re-auth for sensitive records.
- Argon2id high (256 MiB, t=5).
- Auto-lock after 1 minute.
- Vault locked on sleep/lock events.
- Memory locking enabled.
- Root detection with disabled features.
- Debugger detection with termination.
- **Protects against:** Level 2 + significant-resource brute force.

### Level 4: Maximum Security
- Level 3 + Hardware Security Key required (FIDO2/WebAuthn).
- No biometric unlock.
- No KEK caching.
- Per-record re-authentication.
- No autofill.
- Vault wipe after 3 failed attempts.
- Paranoid Argon2id (512 MiB, t=10).
- **Protects against:** Level 3 + sophisticated forensics.

---

## 27. Hardware Security Keys

### FIDO2 / WebAuthn

**Where they make sense:**
- Additional authentication factor for vault unlock (Level 4).
- Device pairing verification.
- Backup authentication method.

**Where they do NOT replace:**
- Master password as root of trust.
- Biometrics as primary unlock mechanism.

---

## 28. Account Model

| Option | Description | Security | Sync |
|---|---|---|---|
| A: No account | Fully local | Best | None |
| B: Local account | Device-local | Good | None |
| C: Optional cloud | Email for sync coordination | Medium | Yes |
| D: Zero-knowledge | Email for identity, E2E data | Best | Yes |
| E: Device-based | Device ID + pubkey as identity | Good | P2P possible |

**Recommended: Hybrid A + D.** No account required for core use. Optional zero-knowledge account for sync. Email is used for identity coordination only — vault data remains E2E encrypted.

---

## 29. Serverless vs Server-Based

| Dimension | Serverless | Local + ZK Server |
|---|---|---|
| Security | Best | Excellent |
| Privacy | Perfect | Perfect (E2E) |
| Complexity | Low | Medium |
| Cost | None | Server hosting |
| Sync | Manual (file transfer) | Automatic (E2E encrypted) |

**Recommendation:** Start serverless, add optional zero-knowledge sync server later.

---

## 30. Supply Chain Security

| Practice | Implementation |
|---|---|
| Dependency pinning | Lock all dependencies to specific versions |
| Dependency auditing | `cargo audit`, Dependabot/Renovate |
| SBOM generation | Generate for each release |
| Minimal dependencies | Audit every dependency |
| Reproducible builds | All releases reproducible from source |
| Signed releases | All packages signed with release key |
| CI/CD hardening | Isolated build environment |
| Build attestation | SLSA provenance for releases |

---

## 31. Logging & Telemetry

**What MUST NOT be logged:**
- Master password or any derived key material
- VEK, KEK, or any encryption keys
- Record plaintexts
- TOTP secrets
- Recovery phrases
- Biometric data
- Ciphertext that might be mistaken for plaintext

**Default: NO telemetry.** Crash reporting opt-in only, local-first, scrubbed. Analytics opt-in only, aggregated, no personal data.

---

## 32. Update Security

```
Update Process:
1. Check for update (user-initiated or periodic)
2. Download over HTTPS
3. Verify Ed25519 signature against embedded public key
4. Verify package hash
5. Verify version ≥ minimum supported
6. Install via platform mechanism
7. Verify new installation signature
```

**Anti-rollback:** Minimum version enforced on unlock. Vault format version only increases.

---

## 33. Database Corruption & Recovery

| Scenario | Impact | Recovery |
|---|---|---|
| Power loss during write | Possible corruption | SQLite WAL recovery |
| Single record corrupted | One record unreadable | Others unaffected |
| Vault metadata corrupted | Cannot unlock | Restore from backup |
| Entire DB lost | Complete data loss | Restore from backup |

**On vault open:**
1. Read vault_metadata
2. Attempt KEK derivation and VEK decryption
3. For each record: attempt DEK and payload decryption
4. Corrupted records flagged, not silently accepted
5. Present successfully decrypted records + list of corrupted ones
6. NEVER delete the vault file (allow recovery attempts)

---

## 34. Performance Analysis

### 34.1 Vault Size Estimates

| Records | Estimated Size |
|---|---|
| 100 | ~50-200 KB |
| 1,000 | ~500 KB - 2 MB |
| 10,000 | ~5-20 MB |
| 100,000 | ~50-200 MB |

### 34.2 Unlock Time

| Operation | Desktop (128 MiB) | Mobile (64 MiB) |
|---|---|---|
| Argon2id | ~1.5-2.0s | ~0.8-1.2s |
| VEK decryption | <1 ms | <1 ms |
| DEK decryption (all) | 10-50 ms | 10-50 ms |
| Record loading | 5-20 ms | 5-20 ms |
| **Total** | **~2s** | **~1-2s** |

**With DUK (cached KEK):** No Argon2id needed. Single AES-GCM decryption. **Total: <100ms**.

### 34.3 Optimizations

1. Lazy decryption (decrypt on demand)
2. Record caching (keep recently accessed decrypted)
3. DEK prefetching for visible records
4. Background re-encryption after VEK rotation
5. Incremental sync (only changed records)

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

## 37. Data Model

### 37.1 Entities

```
Vault
├── vault_id: UUID
├── version: integer
├── created_at: timestamp (encrypted)
├── modified_at: timestamp (encrypted)
├── VEK: 32 bytes (encrypted under KEK)
├── Argon2id parameters
├── vault_salt: 16 bytes
└── VEK wrapping metadata

Record (base entity)
├── record_id: UUID
├── vault_id: UUID
├── record_type: enum (LOGIN, NOTE, CARD, IDENTITY, SSH, TOTP, etc.)
├── DEK: 32 bytes (encrypted under VEK)
├── payload: encrypted blob (encrypted under DEK)
├── created_at: timestamp (encrypted)
├── modified_at: timestamp (encrypted)
├── version: counter
└── aad: bytes

Record subtypes (all stored in payload, encrypted under DEK):
├── LoginRecord
│   ├── name (encrypted)
│   ├── username (encrypted)
│   ├── password (encrypted)
│   ├── url (encrypted)
│   ├── totp_secret (encrypted)
│   └── notes (encrypted)
├── SecureNote
│   ├── title (encrypted)
│   └── content (encrypted)
├── CardRecord
│   ├── cardholder_name (encrypted)
│   ├── number (encrypted)
│   ├── exp_month/year (encrypted)
│   ├── cvv (encrypted)
│   └── notes (encrypted)
├── IdentityRecord
│   ├── full_name (encrypted)
│   ├── address (encrypted)
│   ├── phone (encrypted)
│   ├── email (encrypted)
│   └── ... (encrypted)
├── SSHKeyRecord
│   ├── name (encrypted)
│   ├── private_key (encrypted)
│   ├── public_key (encrypted)
│   └── passphrase (encrypted)
├── TOTPRecord
│   ├── issuer (encrypted)
│   ├── account (encrypted)
│   ├── secret (encrypted)
│   ├── algorithm (plaintext)
│   ├── digits (plaintext)
│   └── period (plaintext)
├── Wi-FiRecord
│   ├── ssid (encrypted)
│   ├── password (encrypted)
│   ├── security_type (encrypted)
│   └── hidden (encrypted)
└── ... (extensible)

Folder
├── folder_id: UUID
├── name (encrypted)
└── parent_id: UUID (for nested folders)

Tag
├── tag_id: UUID
├── name (encrypted)
└── color (plaintext)

Attachment
├── attachment_id: UUID
├── record_id: UUID
├── filename (encrypted)
├── content_type (encrypted)
├── size: integer
├── DEK: 32 bytes (encrypted under VEK, separate from record DEK)
└── encrypted_data: blob (encrypted under attachment DEK)

Device (for sync/pairing)
├── device_id: UUID
├── device_name (encrypted)
├── device_type (plaintext)
├── public_keys (pairing + sharing)
├── last_sync: timestamp
├── created_at: timestamp
└── revoked: boolean

SharePackage
├── package_id: UUID
├── sender_device_id: UUID
├── recipient_public_key: bytes
├── ephemeral_public_key: bytes
├── encrypted_secret: blob
├── nonce: bytes
├── signature: bytes
├── expires_at: timestamp (optional)
├── one_time: boolean
├── used: boolean
└── created_at: timestamp
```

### 37.2 Metadata Classification

| Data | Classification | Stored Plaintext? |
|---|---|---|
| Record type (LOGIN, NOTE, etc.) | Low sensitivity | Yes (needed for UI) |
| Record ID (UUID) | Low sensitivity | Yes (random, no PII) |
| DEK wrapped blob | Protected (encrypted under VEK) | Yes (ciphertext) |
| Folder type | Low sensitivity | Yes |
| Algorithm identifiers | Public | Yes |
| Record timestamps | Medium sensitivity | No (encrypted) |
| Record names | Medium sensitivity | No (encrypted) |
| Record content | High sensitivity | No (encrypted) |
| TOTP secrets | High sensitivity | No (encrypted) |
| Card numbers | High sensitivity | No (encrypted) |
| SSH private keys | High sensitivity | No (encrypted) |

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

## 39. Cryptographic Migration

### 39.1 Migration Strategy

When an algorithm needs to be replaced (e.g., Argon2id parameters need updating, or a new cipher is preferred):

```
Migration Process (no plaintext exposure):
┌────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  State: Vault encrypted with Algorithm A                            │
│                                                                     │
│  Step 1: User unlocks vault with master password                    │
│          KEK = Argon2id(password, salt, params_A)                   │
│          VEK = Decrypt(wrapped_vek_A, KEK)                          │
│          ─── Plaintext is now in RAM only ───                       │
│                                                                     │
│  Step 2: Generate new parameters for Algorithm B                     │
│          new_salt = CSPRNG(16)                                      │
│          new_vek = CSPRNG(32) [or keep same VEK]                    │
│                                                                     │
│  Step 3: Re-encrypt with new parameters                             │
│          new_wrapped_vek = Encrypt(new_vek, new_KEK_B)             │
│          [Update record DEK wrappers if VEK changed]               │
│                                                                     │
│  Step 4: Write new vault file                                      │
│          vault_file = { version_B, salt_B, new_wrapped_vek, ... }  │
│                                                                     │
│  Step 5: Verify new vault can be unlocked                           │
│          (attempt unlock before replacing old file)                │
│                                                                     │
│  Step 6: Atomically replace old vault file with new                 │
│                                                                     │
│  Step 7: Zeroize all intermediate keys from RAM                     │
│                                                                     │
│  Result: Vault now uses Algorithm B.                                │
│          Server never sees plaintext.                               │
│          Migration happens entirely on-device.                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 39.2 Migration Triggers

| Trigger | Action |
|---|---|
| KDF parameters outdated | Re-derive KEK with new params, re-wrap VEK |
| Cipher deprecated | Re-encrypt all records with new cipher |
| Key size insufficient | Generate new keys, re-encrypt |
| Protocol version | Migrate package format, re-encrypt payloads |

### 39.3 Backward Compatibility

- Vault file header contains version + algorithm IDs.
- Old versions are supported for reading (unlock, export).
- Migration to new version happens during normal unlock.
- Minimum supported version enforced: vaults below minimum version must be migrated before use.

---

## 40. Red-Team Analysis

### 40.1 Attacker Scenarios

#### R01: Stolen Encrypted Vault File

**Attack:** Attacker obtains `vault.db` from device backup, sync, or file system.

**Expected result without password:** Attacker has salt, wrapped VEK, Argon2id parameters, but cannot derive KEK without password. Vault is secure.

**Expected result with weak password:** Attacker performs offline dictionary attack. Weak passwords (<30 bits entropy) can be cracked in hours/days.

**Mitigation:** Strong master password (≥60 bits), Argon2id memory hardness, recovery phrase backup.

**Residual risk:** Weak master passwords are vulnerable to offline brute force. User education is essential.

#### R02: Offline Brute-Force

**Attack:** Attacker has vault file and performs optimized GPU-based Argon2id attack.

**Expected result:** ~10,000-50,000 guesses/second on high-end GPU. 6-word Diceware (~78 bits) → ~600 years. 12-character random password (~78 bits) → ~600 years.

**Mitigation:** Argon2id memory hardness, strong password guidance, Device Unlock Key as additional barrier.

**Residual risk:** Economic attacks (nation-state with dedicated ASICs for Argon2id). Acceptable for commercial product targeting individuals and businesses (not nation-state adversaries).

#### R03: Rooted Android Device

**Attack:** Attacker roots device, reads application private storage, extracts vault file. With root, can potentially access Keystore keys.

**Expected result:** Vault file accessible. If Keystore is compromised, DUK and wrapped KEK accessible. Attacker can decrypt VEK without master password.

**Mitigation:** Root detection + warning, disable biometric unlock, require master password. Hardware-backed keys (StrongBox) persist even if OS is compromised — but attacker with root can still call Keystore APIs to decrypt using the hardware key if they can trigger biometric auth.

**Residual risk:** High. Rooted devices fundamentally cannot be trusted. Best mitigation: detect root and require master password.

#### R04: Malware on Device

**Attack:** Keylogger captures master password at input time. Screen scraper captures vault contents. Memory dumper reads RAM.

**Expected result:** Malware with user privileges can capture plaintext secrets.

**Mitigation:** FLAG_SECURE, anti-keylogging input fields, memory zeroization, short auto-lock.

**Residual risk:** HIGH. We cannot fully protect against malware running with user-level access on the same device. This is an OS security boundary issue. We mitigate but cannot eliminate.

#### R05: Compromised Sync Server

**Attack:** Attacker gains access to cloud sync storage (Google Drive, etc.).

**Expected result:** Attacker obtains encrypted vault packages. Without VEK, packages are useless.

**Mitigation:** E2E encryption. VEK never leaves device. Server sees only ciphertext.

**Residual risk:** None for confidentiality. Server could delete or corrupt packages (availability attack). Hash chain provides tamper detection.

#### R06: MITM During Sharing

**Attack:** Attacker intercepts WhatsApp message, modifies share package.

**Expected result:** Ed25519 signature verification fails. Package rejected.

**Mitigation:** Ed25519 sender authentication. Recipient verifies signature before decryption.

**Residual risk:** If recipient does not have sender's verified public key, attacker could substitute their own key. User must verify sender identity through an out-of-band channel.

#### R07: Phishing via Autofill

**Attack:** Malicious website mimics legitimate login form. Autofill provides credentials.

**Expected result:** Credentials sent to attacker's server.

**Mitigation:** Domain verification, user confirmation before autofill, no silent autofill, subdomain checking, IDN/punycode detection.

**Residual risk:** User can still be tricked into manually approving autofill on a phishing site. Domain verification helps but cannot prevent all phishing.

#### R08: Evil Maid

**Attack:** Attacker gains physical access to powered-off device. Boots from external media, extracts disk contents.

**Expected result:** If full-disk encryption is enabled, disk is encrypted. Attacker cannot read vault file without credentials.

**Mitigation:** Full-disk encryption (LUKS, BitLocker, FileVault). Vault is additionally encrypted with VEK.

**Residual risk:** If device is left unlocked and unattended, attacker can access unlocked vault. Auto-lock mitigates this.

#### R09: Malicious Update

**Attack:** Attacker compromises update server, delivers trojanized application.

**Expected result:** Attacker's code runs with full application privileges, can exfiltrate secrets.

**Mitigation:** Signed updates with Ed25519. Unsigned updates rejected. Reproducible builds enable independent verification.

**Residual risk:** If signing key is compromised, attacker can sign malicious updates. Key rotation and HSM storage of signing key mitigate this.

#### R10: Supply Chain Attack

**Attack:** Attacker compromises a popular dependency library, introduces backdoor.

**Expected result:** Backdoor code runs in our application, potentially exfiltrating secrets.

**Mitigation:** Minimal dependencies, dependency auditing (cargo audit), SBOM, reproducible builds, fuzzing, security-focused code review.

**Residual risk:** Sophisticated supply chain attacks (e.g., xz Utils backdoor, 2024) are difficult to detect. Minimizing dependencies and maintaining audit capability reduces risk.

#### R11: Clipboard Exposure

**Attack:** Malicious app monitors clipboard, reads copied password.

**Expected result:** Password captured from clipboard.

**Mitigation:** Auto-clear clipboard after 30 seconds. Warn before copy. No auto-copy.

**Residual risk:** Clipboard monitoring apps can capture clipboard content between our clear and the user's paste. Minimizing hold time reduces window.

#### R12: Screenshot/Screen Recording

**Attack:** Attacker takes screenshot or screen recording while app is visible.

**Expected result:** Secrets visible in screenshot.

**Mitigation:** FLAG_SECURE (Android), platform equivalents on desktop.

**Residual risk:** Rooted/jailbroken devices can bypass FLAG_SECURE. Attacker with physical access can use another device's camera. Cannot prevent physical photography.

#### R13: Compromised Recipient Device

**Attack:** Attacker gains access to recipient's device after share package is delivered.

**Expected result:** Attacker can use recipient's app to view decrypted secret.

**Mitigation:** None — this is a recipient-side security issue, not a transport or protocol issue.

**Residual risk:** INHERENT LIMITATION. We explicitly do not protect against compromised recipient devices. The share protocol protects the secret in transit and ensures only the intended recipient can decrypt. What the recipient does with the plaintext afterward is out of scope.

---

## 41. Security Theater Avoidance

### 41.1 Identified Anti-Patterns

#### ❌ "Multiple Encryption Layers"

**Claim:** "We encrypt the data three times with three different keys for triple protection."

**Reality:** Properly implemented single-layer encryption with a strong key is not weakened by adding more encryption layers. Triple encryption does not meaningfully increase security but increases complexity, attack surface, and the chance of implementation errors. It also creates a false sense of security.

**Verdict:** DO NOT implement. One well-implemented layer with a strong key is sufficient.

#### ❌ "Proprietary Cryptography"

**Claim:** "Our custom encryption algorithm is unbreakable because it's secret."

**Reality:** Kerckhoffs's Principle: a cryptographic system should be secure even if everything about the system is public knowledge except the key. Proprietary algorithms are universally weaker than public, peer-reviewed algorithms.

**Verdict:** DO NOT implement. Use only standard, peer-reviewed algorithms.

#### ❌ "Hiding/Renaming Encrypted Files"

**Claim:** "We hide the vault file with a random name to protect it."

**Reality:** Security through obscurity. An attacker with file system access can find the vault file by scanning for magic bytes or known patterns. The encryption protects the data; the filename does not.

**Verdict:** DO NOT rely on. File naming is irrelevant when data is properly encrypted.

#### ❌ "Biometrics as Encryption Keys"

**Claim:** "Your fingerprint IS your encryption key."

**Reality:** As discussed in §14, biometrics are not secrets, are not consistent, and are not revocable. Using biometrics directly as encryption keys creates security vulnerabilities and usability problems.

**Verdict:** DO NOT implement. Biometrics are a convenience gating mechanism for hardware-backed key release.

#### ❌ "Pretending Screenshot Blocking is Absolute"

**Claim:** "Our app prevents all screenshots."

**Reality:** FLAG_SECURE prevents screenshots from the OS, but cannot prevent:
- Physical cameras photographing the screen
- Rooted devices bypassing FLAG_SECURE
- Screen recording on some platforms
- Memory forensics

**Verdict:** Implement screenshot blocking as a mitigation, but never claim it is absolute. Be honest about limitations.

#### ❌ "Pretending WhatsApp Transport Encryption Protects Plaintext"

**Claim:** "WhatsApp's end-to-end encryption keeps your secrets safe."

**Reality:** WhatsApp's encryption protects the transport channel. Our application-level encryption protects the secret content. These are independent layers. WhatsApp cannot protect our application's plaintext — we must do that ourselves.

**Verdict:** Implement our own encryption regardless of transport. Never rely on transport encryption for application-level security.

#### ❌ "Password Complexity Requirements That Don't Help"

**Claim:** "Passwords must contain uppercase, lowercase, numbers, and special characters."

**Reality:** NIST SP 800-63B explicitly advises against composition rules. They reduce entropy by forcing predictable patterns and don't significantly improve security. Length and entropy matter, not character class diversity.

**Verdict:** Show entropy estimate. Recommend passphrases. No composition rules.

#### ❌ "Security by Obfuscation"

**Claim:** "Our code is obfuscated so attackers can't reverse engineer it."

**Reality:** Security through obscurity does not protect against determined reverse engineering. The cryptographic design must be secure even when fully understood (Kerckhoffs's Principle). Obfuscation may slow down attackers slightly but does not provide real security.

**Verdict:** Obfuscation is fine as a minor additional barrier. Never rely on it as a primary security measure. Security must come from the cryptographic design.

---

## 42. Development Roadmap

### Phase 0: Threat Model + Cryptographic Protocol Design
**Duration:** 4-6 weeks
**Deliverables:** This document, protocol specifications, cryptographic design review
**Exit criteria:** Design approved by security review

### Phase 1: Local Encrypted Vault
**Duration:** 8-12 weeks
**Features:** Master password, vault creation, unlock/lock, record CRUD, Argon2id KDF, XChaCha20-Poly1305 encryption, per-record DEKs, SQLite storage
**Tests:** Unit tests for all crypto operations, integration tests for vault lifecycle, penetration test of vault file
**Risks:** Cryptographic implementation bugs, memory safety

### Phase 2: Android Security Integration
**Duration:** 6-8 weeks
**Features:** Android Keystore integration, biometric unlock, FLAG_SECURE, clipboard management, autofill service, root detection
**Tests:** Keystore integration tests, biometric flow tests, root detection tests
**Risks:** Keystore API differences across Android versions, StrongBox availability

### Phase 3: Desktop Applications
**Duration:** 8-12 weeks
**Features:** Windows (DPAPI + TPM), macOS (Keychain + Secure Enclave), Linux (Secret Service + TPM), cross-platform Rust core
**Tests:** Platform integration tests, key storage/recovery tests
**Risks:** Platform API differences, distribution packaging

### Phase 4: Password Generator + TOTP + Secure Notes
**Duration:** 4-6 weeks
**Features:** Secure password generator with entropy display, TOTP storage and generation, otpauth:// URI import, QR scanning
**Tests:** TOTP correctness (test vectors), password entropy validation
**Risks:** TOTP clock synchronization issues

### Phase 5: Secure Sharing
**Duration:** 6-8 weeks
**Features:** X25519 key exchange, Ed25519 signing, share package creation/decryption, QR-based pairing, WhatsApp/email/QR transport
**Tests:** Protocol conformance tests, MITM simulation tests, interoperability tests
**Risks:** Key verification UX, package format compatibility

### Phase 6: Encrypted Backup
**Duration:** 4-6 weeks
**Features:** Encrypted backup export/import, recovery phrase generation (24 words), recovery key file
**Tests:** Backup/restore cycle tests, recovery phrase tests
**Risks:** User confusion about recovery phrase importance

### Phase 7: Device Pairing
**Duration:** 4-6 weeks
**Features:** Ed25519-based device pairing, QR code exchange, human-verified numeric codes, device revocation
**Tests:** Pairing protocol tests, MITM tests, revocation tests
**Risks:** Pairing UX complexity

### Phase 8: Optional Synchronization
**Duration:** 8-12 weeks
**Features:** Zero-knowledge sync engine, Google Drive/OneDrive/Dropbox/iCloud providers, conflict resolution, version vectors
**Tests:** Sync simulation tests, conflict resolution tests, corruption recovery tests
**Risks:** Conflict resolution edge cases, sync data corruption

### Phase 9: Security Hardening
**Duration:** 4-6 weeks
**Features:** Memory zeroization improvements, anti-debugging, secure UI hardening, performance optimization
**Tests:** Memory forensics tests, side-channel analysis
**Risks:** Platform-specific hardening limitations

### Phase 10: Independent Security Audit
**Duration:** 8-12 weeks (parallel with or after Phase 9)
**Activities:** Cryptography review, source code review, mobile pen testing, desktop pen testing, reverse engineering, binary analysis, fuzzing, dependency audit, protocol analysis
**Exit criteria:** All critical/high findings resolved or accepted with documented risk acceptance

---

## 43. MVP Definition

### Must Have
- Master password with Argon2id KDF
- Vault creation, unlock, lock
- Record CRUD (login, secure note, card at minimum)
- Per-record envelope encryption (XChaCha20-Poly1305)
- Local SQLite storage
- Password generator
- Secure copy with auto-clear clipboard
- Auto-lock with configurable timeout
- Screenshot protection (FLAG_SECURE)
- Encrypted backup (export/import file)
- Recovery phrase (24 words)

### Should Have
- Android (Keystore + biometrics)
- Windows (DPAPI + Windows Hello)
- macOS (Keychain + Touch ID)
- TOTP support
- Secure sharing (QR code)
- Search (in-memory index)

### Later
- Linux support
- Device pairing (Bluetooth/QR)
- Cloud sync (zero-knowledge)
- Browser extension autofill
- Hardware security key support (FIDO2)
- Shamir Secret Sharing recovery
- Attachment support

### Avoid Initially
- Cloud account requirement
- Social login
- Remote password reset (impossible in zero-knowledge)
- Any feature that requires a server for core functionality

---

## 44. Security Audit Checklist

### Cryptography Review
- [ ] Argon2id implementation verified against RFC 9106
- [ ] XChaCha20-Poly1305 implementation verified against RFC 8439
- [ ] All nonce generation uses CSPRNG
- [ ] No nonce reuse in any code path
- [ ] Authentication tags verified before using plaintext
- [ ] Keys properly zeroized after use
- [ ] No custom cryptographic primitives
- [ ] Key hierarchy correctly implemented
- [ ] AAD correctly bound to ciphertext
- [ ] Side-channel analysis of crypto operations

### Source Code Review
- [ ] Memory safety audit (especially unsafe blocks in Rust)
- [ ] No secrets in logs or error messages
- [ ] No secrets in crash dumps
- [ ] FFI boundaries properly validated
- [ ] Input validation on all external data
- [ ] No buffer overflows or integer overflows
- [ ] Race conditions in concurrent code
- [ ] Proper error handling (no information leakage)

### Mobile Penetration Testing
- [ ] Root detection bypass attempts
- [ ] Keystore extraction attempts
- [ ] Memory dump analysis
- [ ] Static analysis of APK/IPA
- [ ] Dynamic analysis (Frida, Xposed)
- [ ] Backup extraction attempts
- [ ] Deep link hijacking
- [ ] Intent interception
- [ ] Accessibility service abuse
- [ ] Overlay attacks

### Desktop Penetration Testing
- [ ] Memory dump analysis
- [ ] Debugger attachment
- [ ] Process injection
- [ ] Credential dumping from OS keychain
- [ ] Swap/page file analysis
- [ ] DLP bypass
- [ ] Binary modification

### Reverse Engineering
- [ ] APK/IPA decompilation
- [ ] Binary analysis (IDA, Ghidra)
- [ ] Symbol stripping verification
- [ ] Anti-tampering bypass attempts
- [ ] Code signing verification

### Binary Analysis
- [ ] Binary diffing between builds
- [ ] Unexpected code inclusion
- [ ] Debug symbols in release builds
- [ ] Stack canaries and ASLR verification

### Fuzzing
- [ ] Vault file parser fuzzing
- [ ] Share package parser fuzzing
- [ ] Input validation fuzzing
- [ ] Protocol state machine fuzzing
- [ ] otpauth:// URI parsing fuzzing

### Dependency Audit
- [ ] cargo audit (Rust)
- [ ] Snyk / Dependabot scan
- [ ] SBOM generation and review
- [ ] License compliance check
- [ ] CVE review for all dependencies

### Protocol Analysis
- [ ] Sharing protocol formal verification
- [ ] Pairing protocol formal verification
- [ ] Sync protocol conflict analysis
- [ ] Replay attack testing
- [ ] MITM attack testing
- [ ] Key compromise simulation

### Secure Storage Testing
- [ ] Keystore extraction on rooted devices
- [ ] DPAPI/Keychain extraction on compromised desktops
- [ ] File permission verification
- [ ] Backup exclusion verification
- [ ] Encryption at rest verification

### Memory Testing
- [ ] Memory dump during vault unlock
- [ ] Key zeroization verification
- [ ] Swap/page file contamination check
- [ ] Core dump analysis
- [ ] Garbage collection behavior analysis

### Backup/Restore Testing
- [ ] Backup file tampering
- [ ] Partial restore (corrupted backup)
- [ ] Cross-version restore
- [ ] Password change during backup window

### Sharing Testing
- [ ] Package tampering
- [ ] Replay attack
- [ ] Expiry enforcement
- [ ] One-time use enforcement
- [ ] Cross-app sharing
- [ ] Transport independence verification

---

## 45. Formal Protocol Specifications

### 45.1 Key Derivation

```
K_KEK = Argon2id(
    P = master_password (UTF-8 encoded),
    S = vault_salt (16 bytes, random),
    K = NULL,
    T = 3,
    M = 128 MiB (desktop) / 64 MiB (mobile),
    p = 4 (desktop) / 2 (mobile),
    d = 1 (data-dependent, Argon2d variant),
    type = Argon2id (hybrid: Argon2i first pass, Argon2d rest)
)
Output: K_KEK (32 bytes)
```

### 45.2 VEK Encryption

```
nonce_vek = CSPRNG(12 bytes)  // AES-GCM nonce
wrapped_vek, tag_vek = AES-256-GCM_Encrypt(
    key = K_KEK,
    nonce = nonce_vek,
    plaintext = VEK (32 bytes),
    ad = AAD_VAULT = "VAULT-v1" || version || vault_salt
)
```

### 45.3 DEK Encryption (Record-Level)

```
nonce_dek = counter_nonce(record_index)  // Deterministic, unique per record
wrapped_dek, tag_dek = AES-256-GCM_Encrypt(
    key = VEK,
    nonce = nonce_dek,
    plaintext = DEK (32 bytes),
    ad = AAD_DEK = "DEK-v1" || record_type || record_id
)

nonce_payload = CSPRNG(24 bytes)  // XChaCha20 nonce
ciphertext, tag_payload = XChaCha20-Poly1305_Encrypt(
    key = DEK,
    nonce = nonce_payload,
    plaintext = record_plaintext,
    ad = AAD_RECORD = "REC-v1" || record_type || record_id
)
```

### 45.4 Sharing Key Derivation

```
// Sender side:
eph_priv = CSPRNG(32 bytes)
eph_pub = X25519(eph_priv)
shared = X25519(eph_priv, recipient_pub_x)
enc_key = HKDF-SHA256(
    ikm = shared,
    salt = eph_pub || recipient_pub_x,
    info = "share-v1-enc",
    length = 32
)
sig = Ed25519_Sign(sender_priv, 
    BLAKE3("SHR1" || eph_pub || recipient_pub_x || sender_pub_x || ciphertext))

// Recipient side:
shared = X25519(recipient_priv, eph_pub)
enc_key = HKDF-SHA256(
    ikm = shared,
    salt = eph_pub || recipient_pub_x,
    info = "share-v1-enc",
    length = 32
)
valid = Ed25519_Verify(sender_pub_x, 
    BLAKE3("SHR1" || eph_pub || recipient_pub_x || sender_pub_x || ciphertext), sig)
```

### 45.5 Pairing Key Exchange

```
// Device A (initiator):
pairing_code = CSPRNG(8)  // 8-digit decimal
dpk_a_priv, dpk_a_pub = Ed25519_KeyGen()
display_code = dpk_a_pub || pairing_code

// Device B (responder):
dpk_b_priv, dpk_b_pub = Ed25519_KeyGen()
sig_b = Ed25519_Sign(dpk_b_priv, dpk_a_pub || dpk_b_pub || pairing_code)

// Device A verifies:
valid_a = Ed25519_Verify(dpk_b_pub, dpk_a_pub || dpk_b_pub || pairing_code, sig_b)
// User confirms both devices display same pairing_code
// If valid_a and user confirms → pairing established
```

---

## 46. Final Deliverables & Status

This document provides:

| Deliverable | Section | Status |
|---|---|---|
| Executive summary | §1 | Complete |
| Security principles | §2 | Complete |
| Threat model | §3 | Complete |
| Trust boundaries | §4 | Complete |
| Architecture diagram | §4 | Complete (ASCII) |
| Cryptographic architecture | §5 | Complete |
| Complete key hierarchy | §6 | Complete |
| Key lifecycle | §7 | Complete |
| Database architecture | §10 | Complete |
| Encryption format | §38 | Complete |
| Sharing protocol | §15 | Complete |
| Device-pairing protocol | §17 | Complete |
| Backup/recovery architecture | §19 | Complete |
| Optional sync architecture | §18 | Complete |
| Android architecture | §12 | Complete |
| Windows architecture | §13.1 | Complete |
| macOS architecture | §13.2 | Complete |
| Linux architecture | §13.3 | Complete |
| Authentication architecture | §8 | Complete |
| Biometric architecture | §14 | Complete |
| Autofill architecture | §22 | Complete |
| TOTP architecture | §21 | Complete |
| Clipboard security | §24 | Complete |
| Memory security | §23 | Complete |
| Metadata privacy analysis | §11 | Complete |
| Supply-chain security | §30 | Complete |
| Update security | §32 | Complete |
| Logging/telemetry policy | §31 | Complete |
| Attack analysis / Red-team | §40 | Complete |
| Security theater avoidance | §41 | Complete |
| Recommended tech stack | §35 | Complete |
| Recommended crypto libraries | §36 | Complete |
| Database schema | §37 | Complete |
| Package formats | §38 | Complete |
| Cryptographic migration | §39 | Complete |
| Development roadmap | §42 | Complete |
| Testing strategy | §44 | Complete |
| Security audit checklist | §44 | Complete |

### Major Architectural Decisions

1. **XChaCha20-Poly1305** for record encryption (over AES-GCM)
2. **Argon2id** for master password key derivation (over PBKDF2, scrypt)
3. **Per-record envelope encryption** with DEKs wrapped under VEK (over single-key vault)
4. **Application-level encryption** over SQLCipher (for granularity and portability)
5. **Rust** for cryptographic core (for memory safety and zeroize guarantees)
6. **Biometrics as convenience unlock only** (never as encryption key)
7. **Local-first, serverless core** with optional zero-knowledge sync
8. **Transport-agnostic sharing** with X25519 + Ed25519 envelope
9. **Honest recovery model** — no backdoors, user controls recovery material

### Major Unresolved Risks

1. **User master password quality.** The weakest link is the user's password. Education helps but cannot eliminate weak passwords.
2. **Rooted/jailbroken devices.** Cannot be secured against determined attackers with root.
3. **Malware on same device.** OS-level problem that application-level security cannot fully solve.
4. **User losing all recovery material.** Zero-knowledge means no recovery without user's keys.
5. **Quantum computing.** X25519 and Ed25519 are not post-quantum. Future migration to hybrid PQ schemes needed.
6. **Sync conflict resolution.** Last-write-wins may lose data in edge cases. Manual resolution UX needs validation.
7. **Long-term maintenance.** Cryptographic agility requires ongoing maintenance as algorithms age.

---

*End of document.*
