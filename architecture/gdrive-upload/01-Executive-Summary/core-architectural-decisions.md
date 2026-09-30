# Core Architectural Decisions

**Source:** §1 — Secret Manager Architecture Study

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
