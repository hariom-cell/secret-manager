# 37.1 Entities

**Source:** §37 — Secret Manager Architecture Study

---

## 37. Data Model

### 37.1 Entities

```
Vault
├── vault_id: UUID
├── version: integer
├── created_at: timestamp (encrypted)
├── modified_at: timestamp (encrypted)
├── VEK: 32 bytes (encrypted under KEK)
├── Argon2id parameters
├── vault_salt: 16 bytes
└── VEK wrapping metadata

Record (base entity)
├── record_id: UUID
├── vault_id: UUID
├── record_type: enum (LOGIN, NOTE, CARD, IDENTITY, SSH, TOTP, etc.)
├── DEK: 32 bytes (encrypted under VEK)
├── payload: encrypted blob (encrypted under DEK)
├── created_at: timestamp (encrypted)
├── modified_at: timestamp (encrypted)
├── version: counter
└── aad: bytes

Record subtypes (all stored in payload, encrypted under DEK):
├── LoginRecord
│   ├── name (encrypted)
│   ├── username (encrypted)
│   ├── password (encrypted)
│   ├── url (encrypted)
│   ├── totp_secret (encrypted)
│   └── notes (encrypted)
├── SecureNote
│   ├── title (encrypted)
│   └── content (encrypted)
├── CardRecord
│   ├── cardholder_name (encrypted)
│   ├── number (encrypted)
│   ├── exp_month/year (encrypted)
│   ├── cvv (encrypted)
│   └── notes (encrypted)
├── IdentityRecord
│   ├── full_name (encrypted)
│   ├── address (encrypted)
│   ├── phone (encrypted)
│   ├── email (encrypted)
│   └── ... (encrypted)
├── SSHKeyRecord
│   ├── name (encrypted)
│   ├── private_key (encrypted)
│   ├── public_key (encrypted)
│   └── passphrase (encrypted)
├── TOTPRecord
│   ├── issuer (encrypted)
│   ├── account (encrypted)
│   ├── secret (encrypted)
│   ├── algorithm (plaintext)
│   ├── digits (plaintext)
│   └── period (plaintext)
├── Wi-FiRecord
│   ├── ssid (encrypted)
│   ├── password (encrypted)
│   ├── security_type (encrypted)
│   └── hidden (encrypted)
└── ... (extensible)

Folder
├── folder_id: UUID
├── name (encrypted)
└── parent_id: UUID (for nested folders)

Tag
├── tag_id: UUID
├── name (encrypted)
└── color (plaintext)

Attachment
├── attachment_id: UUID
├── record_id: UUID
├── filename (encrypted)
├── content_type (encrypted)
├── size: integer
├── DEK: 32 bytes (encrypted under VEK, separate from record DEK)
└── encrypted_data: blob (encrypted under attachment DEK)

Device (for sync/pairing)
├── device_id: UUID
├── device_name (encrypted)
├── device_type (plaintext)
├── public_keys (pairing + sharing)
├── last_sync: timestamp
├── created_at: timestamp
└── revoked: boolean

SharePackage
├── package_id: UUID
├── sender_device_id: UUID
├── recipient_public_key: bytes
├── ephemeral_public_key: bytes
├── encrypted_secret: blob
├── nonce: bytes
├── signature: bytes
├── expires_at: timestamp (optional)
├── one_time: boolean
├── used: boolean
└── created_at: timestamp
```

### 37.2 Metadata Classification

| Data | Classification | Stored Plaintext? |
|---|---|---|
| Record type (LOGIN, NOTE, etc.) | Low sensitivity | Yes (needed for UI) |
| Record ID (UUID) | Low sensitivity | Yes (random, no PII) |
| DEK wrapped blob | Protected (encrypted under VEK) | Yes (ciphertext) |
| Folder type | Low sensitivity | Yes |
| Algorithm identifiers | Public | Yes |
| Record timestamps | Medium sensitivity | No (encrypted) |
| Record names | Medium sensitivity | No (encrypted) |
| Record content | High sensitivity | No (encrypted) |
| TOTP secrets | High sensitivity | No (encrypted) |
| Card numbers | High sensitivity | No (encrypted) |
| SSH private keys | High sensitivity | No (encrypted) |

---
