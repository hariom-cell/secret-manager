# 6.1 Key-by-Key Analysis

**Source:** §6 — Secret Manager Architecture Study

---

## 6. Key Hierarchy

```
┌──────────────────────────────────────────────────────────────────────┐
│                      COMPLETE KEY HIERARCHY                           │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Master Password (human-remembered)                         │      │
│  │  NEVER STORED. Only exists during unlock.                   │      │
│  └────────────────────┬───────────────────────────────────────┘      │
│                       │ Argon2id(password, salt, params)             │
│                       ▼                                               │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Key Encryption Key (KEK) ─── 32 bytes                     │      │
│  │  Derived from master password. NOT stored.                  │      │
│  │  Exists only in RAM during unlock.                          │      │
│  └────────────────────┬───────────────────────────────────────┘      │
│                       │ encrypts/decrypts                            │
│                       ▼                                               │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Vault Encryption Key (VEK) ─── 32 bytes                   │      │
│  │  Randomly generated. Stored encrypted under KEK.            │      │
│  │  Decrypts entire vault payload.                             │      │
│  └────────────────────┬───────────────────────────────────────┘      │
│                       │ encrypts/decrypts                            │
│                       ▼                                               │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Vault Payload                                              │      │
│  │  Contains:                                                  │      │
│  │  - Per-record Data Encryption Keys (DEKs)                   │      │
│  │  - Encrypted record blobs                                   │      │
│  │  - Encrypted metadata                                       │      │
│  └────────────────────────────────────────────────────────────┘      │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Per-Record Data Encryption Key (DEK) ── 32 bytes          │      │
│  │  Random per record. Stored encrypted under VEK.             │      │
│  │  Encrypts one record's plaintext.                           │      │
│  │  Allows individual record re-encryption.                    │      │
│  └────────────────────┬───────────────────────────────────────┘      │
│                       │ encrypts                                      │
│                       ▼                                               │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Record Ciphertext ─ XChaCha20-Poly1305                    │      │
│  │  (nonce, encrypted_data, tag)                               │      │
│  └────────────────────────────────────────────────────────────┘      │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Device Unlock Key (DUK)                                   │      │
│  │  Hardware-backed (Keystore/SE/TPM). Non-exportable.         │      │
│  │  Wraps cached KEK for fast biometric unlock.                │      │
│  └────────────────────┬───────────────────────────────────────┘      │
│                       │ authorizes                                    │
│                       ▼                                               │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Wrapped KEK Cache                                          │      │
│  │  KEK encrypted under DUK. Stored in app private storage.    │      │
│  │  Avoids Argon2id on every unlock.                           │      │
│  └────────────────────────────────────────────────────────────┘      │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Device Pairing Key (DPK) ─ Ed25519 key pair               │      │
│  │  Private key in hardware keystore. Used for pairing auth.   │      │
│  └────────────────────────────────────────────────────────────┘      │
│                                                                      │
│  ┌────────────────────────────────────────────────────────────┐      │
│  │  Sharing Identity Key (SIK)                                │      │
│  │  X25519 + Ed25519 key pairs for sharing.                    │      │
│  │  Private keys in hardware keystore.                         │      │
│  └────────────────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────────────┘
```

### 6.1 Key-by-Key Analysis

#### KEK (Key Encryption Key)

| Property | Value |
|---|---|
| **Creator** | Application, during vault creation or master password change |
| **Generation** | Argon2id(master_password, vault_salt, parameters) |
| **Size** | 32 bytes |
| **Persistence** | Never directly persisted. Re-derivable from master password. Optionally cached encrypted under DUK. |
| **Protection** | Requires master password to derive. If DUK cache is used, additionally gated by biometrics/device credential. |
| **Compromise impact** | Full vault access. Attacker can decrypt VEK and all records. |
| **Rotation** | Re-derived on master password change. |

**Key insight:** The KEK is never stored. It can always be re-derived. There is no KEK to steal. The only attack vector is online/offline brute-force of the master password — mitigated by Argon2id parameters.

#### VEK (Vault Encryption Key)

| Property | Value |
|---|---|
| **Creator** | Application, during vault creation |
| **Generation** | CSPRNG (32 random bytes) |
| **Size** | 32 bytes |
| **Persistence** | Stored encrypted under KEK. Never in plaintext on disk. |
| **Protection** | Encrypted by KEK. KEK requires master password. |
| **Compromise impact** | Full vault access (but attacker still needs KEK to decrypt VEK). |
| **Rotation** | Triggered by master password change. Old VEK decrypted with old KEK, re-encrypted with new KEK. |

**Key insight:** The VEK is a randomly generated key. Its security is entirely dependent on the KEK protecting it.

#### DEK (Data Encryption Key)

| Property | Value |
|---|---|
| **Creator** | Application, during record creation |
| **Generation** | CSPRNG (32 random bytes per record) |
| **Size** | 32 bytes |
| **Persistence** | Stored encrypted under VEK, bundled with each record. |
| **Protection** | Encrypted by VEK → encrypted by KEK → requires master password. |
| **Compromise impact** | Single record compromised only. |
| **Rotation** | Per-record re-encryption when record is modified. |

**Key insight:** Per-record DEKs enable granular key rotation. When VEK is rotated, all DEK wrappers are re-encrypted. Individual record plaintexts remain encrypted under their DEKs.

#### Device Unlock Key (DUK)

| Property | Value |
|---|---|
| **Creator** | Platform Keystore/Keychain |
| **Generation** | Hardware or OS-generated asymmetric key pair. Private key non-exportable. |
| **Persistence** | Private key in hardware secure element. Cannot be extracted. |
| **Protection** | Hardware-backed. Biometric/device credential gated for use. |
| **Compromise impact** | Allows biometric unlock without master password. Does not compromise vault keys directly. |
| **Rotation** | Application generates new wrapped KEK when DUK changes. |

**Key insight:** The DUK never protects secrets directly. It only wraps a cached copy of the KEK. If the DUK is lost (device replaced), the user enters their master password to re-derive the KEK. Biometric unlock is a **convenience feature**, not a security boundary.

#### Device Pairing Key (DPK)

| Property | Value |
|---|---|
| **Creator** | Application, during device pairing |
| **Generation** | Ed25519 key pair |
| **Persistence** | Private key in hardware keystore. |
| **Compromise impact** | Could impersonate paired device. Vault keys NOT at risk. |
| **Rotation** | New pairing generates new key pair. Old pairings can be revoked. |

#### Sharing Identity Key (SIK)

| Property | Value |
|---|---|
| **Creator** | Application, during first share |
| **Generation** | X25519 + Ed25519 key pairs |
| **Persistence** | Private keys in hardware keystore. |
| **Compromise impact** | Could impersonate user for share creation. Full vault NOT at risk. |
| **Rotation** | User-initiated. Old SIK public key published as revoked. |

---
