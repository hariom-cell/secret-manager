# Cryptography Review

**Source:** §44 — Secret Manager Architecture Study

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
