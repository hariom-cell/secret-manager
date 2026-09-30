# 13.1 Windows

**Source:** §13 — Secret Manager Architecture Study

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
