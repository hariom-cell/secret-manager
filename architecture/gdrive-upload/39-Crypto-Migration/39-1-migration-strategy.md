# 39.1 Migration Strategy

**Source:** §39 — Secret Manager Architecture Study

---

## 39. Cryptographic Migration

### 39.1 Migration Strategy

When an algorithm needs to be replaced (e.g., Argon2id parameters need updating, or a new cipher is preferred):

```
Migration Process (no plaintext exposure):
┌────────────────────────────────────────────────────────────────────┐
│                                                                     │
│  State: Vault encrypted with Algorithm A                            │
│                                                                     │
│  Step 1: User unlocks vault with master password                    │
│          KEK = Argon2id(password, salt, params_A)                   │
│          VEK = Decrypt(wrapped_vek_A, KEK)                          │
│          ─── Plaintext is now in RAM only ───                       │
│                                                                     │
│  Step 2: Generate new parameters for Algorithm B                     │
│          new_salt = CSPRNG(16)                                      │
│          new_vek = CSPRNG(32) [or keep same VEK]                    │
│                                                                     │
│  Step 3: Re-encrypt with new parameters                             │
│          new_wrapped_vek = Encrypt(new_vek, new_KEK_B)             │
│          [Update record DEK wrappers if VEK changed]               │
│                                                                     │
│  Step 4: Write new vault file                                      │
│          vault_file = { version_B, salt_B, new_wrapped_vek, ... }  │
│                                                                     │
│  Step 5: Verify new vault can be unlocked                           │
│          (attempt unlock before replacing old file)                │
│                                                                     │
│  Step 6: Atomically replace old vault file with new                 │
│                                                                     │
│  Step 7: Zeroize all intermediate keys from RAM                     │
│                                                                     │
│  Result: Vault now uses Algorithm B.                                │
│          Server never sees plaintext.                               │
│          Migration happens entirely on-device.                       │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 39.2 Migration Triggers

| Trigger | Action |
|---|---|
| KDF parameters outdated | Re-derive KEK with new params, re-wrap VEK |
| Cipher deprecated | Re-encrypt all records with new cipher |
| Key size insufficient | Generate new keys, re-encrypt |
| Protocol version | Migrate package format, re-encrypt payloads |

### 39.3 Backward Compatibility

- Vault file header contains version + algorithm IDs.
- Old versions are supported for reading (unlock, export).
- Migration to new version happens during normal unlock.
- Minimum supported version enforced: vaults below minimum version must be migrated before use.

---
