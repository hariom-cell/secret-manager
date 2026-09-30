# section-31

**Source:** §31 — Secret Manager Architecture Study

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
