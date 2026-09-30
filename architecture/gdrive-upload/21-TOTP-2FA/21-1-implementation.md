# 21.1 Implementation

**Source:** §21 — Secret Manager Architecture Study

---

## 21. TOTP / 2FA

### 21.1 Implementation

- TOTP secret stored encrypted with record's DEK.
- Generation: HMAC-SHA1(secret, floor(unix_time/30)) → 6/8 digit code.
- Display: code with countdown timer, auto-refresh, auto-clear after inactivity.
- Import: parse `otpauth://` URI, extract secret/issuer/account/algorithm.
- QR scanning: camera or image-based QR scanner.

---
