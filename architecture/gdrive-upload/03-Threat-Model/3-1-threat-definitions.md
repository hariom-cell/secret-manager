# 3.1 Threat Definitions

**Source:** §3 — Secret Manager Architecture Study

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
