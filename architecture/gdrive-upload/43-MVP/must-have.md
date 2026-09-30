# Must Have

**Source:** §43 — Secret Manager Architecture Study

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
