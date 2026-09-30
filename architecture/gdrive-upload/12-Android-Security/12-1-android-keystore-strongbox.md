# 12.1 Android Keystore & StrongBox

**Source:** §12 — Secret Manager Architecture Study

---

## 12. Android Security Architecture

### 12.1 Android Keystore & StrongBox

**Android Keystore** is the platform's secure key storage. Keys stored in the Keystore:
- Cannot be extracted (private key material never leaves secure hardware).
- Can be hardware-backed (TEE or StrongBox).
- Can be gated by biometric authentication.
- Can be bound to specific authentication validity periods.

**StrongBox** (Android 9+, required on Android 14+ for biometric-bound keys):
- Dedicated secure element (hardware security module on-die).
- Independent CPU, RAM, and secure storage.
- FIPS 140-2 Level 3 certified.
- Available on most modern devices (Pixel 3+, Samsung S10+, etc.).

**Fallback:** TEE-backed Keystore keys. Software-backed keys (last resort — warn user). Use `KeyInfo.isInsideSecureHardware()` to check.

### 12.2 Biometric Integration

```kotlin
val keyGen = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
)
val keySpec = KeyGenParameterSpec.Builder("device_unlock_key",
    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationValidityDurationSeconds(30)
    .setStrongBoxBacked(true)
    .build()
keyGen.init(keySpec)
keyGen.generateKey()
```

### 12.3 Security Controls

| Control | Implementation | Security Effect |
|---|---|---|
| **FLAG_SECURE** | `window.setFlags(FLAG_SECURE, FLAG_SECURE)` | Prevents screenshots, screen recording, recent-apps preview |
| **Clipboard protection** | Auto-clear on vault lock; warn before copy | Prevents clipboard persistence |
| **Autofill service** | Implement `AutofillService` with domain verification | Secure autofill |
| **Notification privacy** | `setVisibility(Notification.VISIBILITY_SECRET)` | No content in lock screen notifications |
| **App lock timeout** | Auto-lock after configurable period (default 5 min) | Limits window of opportunity |
| **Root detection** | Check su binary, Magisk, dangerous props | Warn user, disable biometric unlock |
| **Debugger detection** | `Debug.isDebuggerConnected()` | Warn or disable features |
| **APK integrity** | Verify signing certificate at runtime | Detect tampered APK |
| **Backup exclusion** | `android:allowBackup="false"` | Prevents adb backup |
| **Play App Signing** | Google Play App Signing | Google manages signing key |

### 12.4 Rooted Device Behavior

```
If rooted:
├── WARN user prominently on first launch
├── DISABLE biometric unlock
├── DISABLE Device Unlock Key caching
├── REQUIRE master password for every unlock
├── INCREASE Argon2id parameters (if user consents)
├── BLOCK backup/sync features
└── LOG detection (local only, not transmitted)
```

**Honest assessment:** Root detection is inherently a cat-and-mouse game. Magisk Hide, KernelSU, and zygisk can hide root. A determined attacker on a rooted device can read application private storage, capture screen content, intercept touch input, and dump process memory.

**Mitigation:** Use hardware-backed Keystore keys (persist even if OS compromised), require master password for unlock, minimize plaintext lifetime in memory.

### 12.5 Android Backup

- `android:allowBackup="false"` prevents Android Auto Backup and adb backup.
- Our own encrypted backup: user-initiated, encrypted with separate password.

---
