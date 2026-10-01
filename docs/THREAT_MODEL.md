# Threat Model — Secret Manager

## 1. Scope

This document covers the threat model for **vault-core**, **vault-db**, **vault-sdk**, and all platform wrappers. The focus is on the cryptographic vault's confidentiality and integrity guarantees.

Out of scope:
- OS-level memory protection (swap, hibernation, core dumps)
- Supply-chain attacks against compiler/toolchain
- Physical access to the running machine
- Side-channel attacks (cache timing, power analysis)

---

## 2. Assets

| Asset | Classification | Protection Goal |
|-------|---------------|-----------------|
| Master password (in transit / in memory) | Secret | Zeroize on process exit |
| Vault Encryption Key (VEK) | Secret | Never written to disk, derived on-demand |
| Key Encryption Key (KEK) | Secret | Derived via Argon2id, not stored |
| Salt | Semi-public | Stored in header; aids attacker but not sufficient |
| Encrypted records | Sensitive | Confidentiality via XChaCha20-Poly1305 |
| HMAC tags | Integrity | Authenticate ciphertext and nonce |
| Recovery phrase | Secret | Equivalent to master password; 128-bit entropy |

---

## 3. Trust Boundaries

```
┌──────────────────────────────────────────────────────────┐
│  Process memory (untrusted — zeroized on exit)            │
│  ┌────────────┐  ┌────────────┐  ┌──────────────────┐  │
│  │ Master     │  │ VEK (RAM)  │  │ Record keys      │  │
│  │ password   │→ │ ephemeral  │→ │ derived per-ID   │  │
│  └────────────┘  └────────────┘  └──────────────────┘  │
│                          ↓ decrypt                       │
│  ┌──────────────────────────────────────────────────┐   │
│  │  vault-db (vault.enc on disk)                     │   │
│  │  Header: salt ‖ kdf_params ‖ vek_ciphertext ‖ hmac│   │
│  │  Records: nonce ‖ ciphertext ‖ tag                │   │
│  └──────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘

Attacker can read:
  - vault.enc file (full ciphertext)
  - Process memory (before zeroization)
  - Swap / hibernation file (if OS allows)
  - Command-line arguments / process table

Attacker CANNOT (by design):
  - Decrypt records without master password or recovery phrase
  - Forge ciphertext (HMAC verified)
  - Reuse nonces (24-byte random nonces)
  - Impersonate without credentials
```

---

## 4. Threat Actors

### 4.1 Passive Network Attacker
- **Capability**: Read vault.enc from disk/network
- **Mitigation**: XChaCha20-Poly1305 provides IND-CCA2. Attacker gets only random bytes.

### 4.2 Malware / Local Process
- **Capability**: Read vault.enc, memory, swap, keylog
- **Mitigation**:
  - Zeroize: all secrets cleared from RAM on drop/exit
  - No session state: CLI opens and closes vault each invocation
  - OS swap encryption is out of scope (user should enable FileVault/bitlocker/LUKS)
  - Trusted Platform Module (TPM) integration is future work

### 4.3 Phishing / 
- **Capability**: Trick user into entering password on fake UI
- **Mitigation**: Not a code concern. User education / hardware key integration is future work.

### 4.4 Insider / Backup Exposure
- **Capability**: Access to backups, old disk images
- **Mitigation**:
  - Key material never stored; always derived
  - Old passwords cannot be recovered (forward secrecy of Argon2id)

### 4.5 Recovery Phrase Interception
- **Capability**: Steal written-down phrase
- **Mitigation**:
  - Phrase has same entropy as master password (128-bit)
  - User must store phrase separately from vault file
  - Future: Shamir Secret Sharing (2-of-3 split)

---

## 5. Security Controls

| Control | Implementation | Status |
|---------|---------------|--------|
| AEAD encryption | XChaCha20-Poly1305 (libsodium) | ✅ Implemented |
| Key derivation | Argon2id (t=3, m=64MB, p=2) | ✅ Implemented |
| VEK wrapping | AES-256-GCM | ✅ Implemented |
| Nonce generation | CSPRNG (rand::OsRng / ChaCha20) | ✅ Implemented |
| HMAC integrity | HMAC-SHA-256 on header + records | ✅ Implemented |
| Memory zeroization | zeroize crate on all Secret types | ✅ Implemented |
| No-session CLI | Process exit = key destruction | ✅ Implemented |
| Input validation | All bounds checked, no unsafe | ✅ Implemented |
| Dependency audit | cargo-audit, cargo-deny CI | ✅ Implemented |
| Fuzzing | proptest (11 tests) + cargo-fuzz harnesses | ✅ Implemented |
| Recovery phrase | BIP-39-style 8-word phrase, 128-bit | ✅ Implemented |

---

## 6. Residual Risks

1. **OS swap**: Secrets may be paged to disk. Mitigated by OS-level disk encryption.
2. **Process memory**: Secrets are in RAM during use. Mitigated by zeroization and short-lived process.
3. **Clock / entropy**: CSPRNG requires OS entropy. On headless servers with poor entropy, key quality may degrade.
4. **Salt exposure**: Salt is stored in the file header. It is not secret but aids dictionary attacks.
5. **Single factor**: Master password is the sole authentication factor. Adding TOTP or hardware key support is future work.

---

## 7. Future Hardening

- [ ] TOTP second factor (vault-sdk::totp exists, needs CLI integration)
- [ ] Hardware key support (FIDO2 / WebAuthn)
- [ ] Shamir Secret Sharing for recovery (split phrase into 3-of-5)
- [ ] Memory locking (mlock) to prevent swap
- [ ] Constant-time password comparison (already used for records, extend to unlock)
- [ ] Encrypted swap detection warning
- [ ] Audit logging (who unlocked, when)
- [ ] Vault file format versioning and migration
