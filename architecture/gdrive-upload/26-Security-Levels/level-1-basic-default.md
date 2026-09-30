# Level 1: Basic (Default)

**Source:** §26 — Secret Manager Architecture Study

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
