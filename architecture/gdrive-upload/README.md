# Secret Manager — Security Architecture Study

**For Google Drive:** Upload this entire folder structure to `hariomsehgal@gmail.com > sec-manager`.

**Document version:** 1.0 — September 2026
**Total sections:** 46

---

## Folder Structure

```
sec-manager/
├── README.md                        ← You are here
│
├── 01-Executive-Summary/
│   └── core-architectural-decisions.md
│
├── 02-Security-Principles/
│   └── p1-zero-knowledge-by-default.md
│
├── 03-Threat-Model/
│   └── 3-1-threat-definitions.md
│
├── 04-Trust-Boundaries/
│   └── section-4.md
│
├── 05-Cryptographic-Architecture/
│   └── 5-1-primitive-selection.md
│
├── 06-Key-Hierarchy/
│   └── 6-1-key-by-key-analysis.md
│
├── 07-Key-Lifecycle/
│   └── 7-1-vault-creation.md
│
├── 08-Master-Password-Auth/
│   └── 8-1-argon2id-parameters.md
│
├── 09-Record-Encryption/
│   └── 9-1-strategy-envelope-encryption-per-record-deks.md
│
├── 10-Encrypted-Database/
│   └── 10-1-architecture-decision-application-level-envelope-encryp.md
│
├── 11-Metadata-Privacy/
│   └── 11-1-threat-assessment.md
│
├── 12-Android-Security/
│   └── 12-1-android-keystore-strongbox.md
│
├── 13-Desktop-Security/
│   └── 13-1-windows.md
│
├── 14-Biometric-Auth/
│   └── 14-1-design-principle.md
│
├── 15-Secret-Sharing/
│   └── 15-1-protocol-x25519-ed25519-envelope.md
│
├── 16-WhatsApp-Transport/
│   └── 16-1-security-boundary.md
│
├── 17-Device-Pairing/
│   └── 17-1-protocol.md
│
├── 18-Synchronization/
│   └── 18-1-architecture.md
│
├── 19-Backup-Recovery/
│   └── 19-1-recovery-options.md
│
├── 20-Password-Generator/
│   └── 20-1-design.md
│
├── 21-TOTP-2FA/
│   └── 21-1-implementation.md
│
├── 22-Autofill/
│   └── 22-1-android-autofill.md
│
├── 23-Memory-Security/
│   └── 23-1-plaintext-lifetime.md
│
├── 24-Clipboard-Security/
│   └── section-24.md
│
├── 25-Secure-UI/
│   └── section-25.md
│
├── 26-Security-Levels/
│   └── level-1-basic-default.md
│
├── 27-Hardware-Security-Keys/
│   └── fido2-webauthn.md
│
├── 28-Account-Model/
│   └── section-28.md
│
├── 29-Serverless-vs-Server/
│   └── section-29.md
│
├── 30-Supply-Chain/
│   └── section-30.md
│
├── 31-Logging-Telemetry/
│   └── section-31.md
│
├── 32-Update-Security/
│   └── section-32.md
│
├── 33-Database-Corruption/
│   └── section-33.md
│
├── 34-Performance/
│   └── 34-1-vault-size-estimates.md
│
├── 35-Tech-Stack/
│   └── 35-1-evaluation-criteria.md
│
├── 36-Crypto-Libraries/
│   └── 36-1-recommended-libraries.md
│
├── 37-Data-Model/
│   └── 37-1-entities.md
│
├── 38-Package-Formats/
│   └── 38-1-vault-file-format.md
│
├── 39-Crypto-Migration/
│   └── 39-1-migration-strategy.md
│
├── 40-Red-Team/
│   └── 40-1-attacker-scenarios.md
│
├── 41-Security-Theater/
│   └── 41-1-identified-anti-patterns.md
│
├── 42-Roadmap/
│   └── phase-0-threat-model-cryptographic-protocol-design.md
│
├── 43-MVP/
│   └── must-have.md
│
├── 44-Audit-Checklist/
│   └── cryptography-review.md
│
├── 45-Protocol-Specs/
│   └── 45-1-key-derivation.md
│
└── 46-References-Sources/
    └── major-architectural-decisions.md
```

---

## Upload to Google Drive

**Steps:**

1. Go to [Google Drive](https://drive.google.com) in your browser (logged into `hariomsehgal@gmail.com`)
2. Create a new folder named `sec-manager`
3. Open `sec-manager`, create sub-folders `01` through `46` (or use the names above)
4. Upload each `.md` file to its corresponding folder

**Faster method — using rclone (if configured):**

```bash
# Configure rclone for Google Drive first (rclone config)
rclone mkdir hariomsehgal:sec-manager
rclone copy gdrive-upload/ hariomsehgal:sec-manager/ --progress
```

---

## Document Info

- **Total lines:** ~2,536 (master document)
- **Sections:** 46
- **Files:** 46 markdown files + this index
