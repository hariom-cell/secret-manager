# 7.1 Vault Creation

**Source:** §7 — Secret Manager Architecture Study

---

## 7. Key Lifecycle

### 7.1 Vault Creation

```
1. User chooses master password
2. Generate 16-byte random salt (vault_salt)
3. Generate 32-byte random VEK
4. KEK = Argon2id(master_password, vault_salt, m=128MiB, t=3, p=4)
5. wrapped_vek = AES-256-GCM_Encrypt(KEK, nonce, VEK, AAD=vault_metadata)
6. vault_file = { version, algorithm_ids, vault_salt, kdf_parameters, wrapped_vek, encrypted_vault_payload }
7. Zeroize KEK from memory
8. Store vault_file in application private storage
```

### 7.2 Vault Unlock

```
1. Read vault_file from storage
2. Prompt user for master password
3. KEK = Argon2id(master_password, vault_salt, m=128MiB, t=3, p=4)
4. VEK = AES-256-GCM_Decrypt(KEK, nonce, wrapped_vek, tag, AAD=vault_metadata)
5. If decryption fails → WRONG PASSWORD (abort)
6. If decryption succeeds → VEK is now in RAM
7. Decrypt vault_payload with VEK
8. Load records into decrypted in-memory cache
9. Zeroize KEK from memory (VEK remains for session)
```

### 7.3 Vault Lock

```
1. Zeroize all plaintext records from memory
2. Zeroize VEK from memory
3. Clear all cached plaintext
4. Invalidate any cached KEK wrap
5. Lock UI — require re-authentication
6. Revoke any in-flight biometric auth tokens
```

### 7.4 Master Password Change

```
1. User provides old master password + new master password
2. Derive old_KEK = Argon2id(old_password, vault_salt, m=128MiB, t=3, p=4)
3. Decrypt VEK with old_KEK
4. Generate new vault_salt (16 bytes random)
5. Derive new_KEK = Argon2id(new_password, new_salt, m=128MiB, t=3, p=4)
6. Re-encrypt VEK with new_KEK
7. Store new vault_salt + new wrapped VEK
8. DEKs remain encrypted under VEK (no re-encryption needed)
9. Zeroize old_KEK and old password strings from memory
```

**Why individual record plaintexts don't need re-encryption:** Records are encrypted with per-record DEKs. DEKs are encrypted under the VEK. Changing the master password changes the KEK (which wraps the VEK), which wraps all DEK metadata. Individual record plaintexts remain encrypted under their DEKs — which are still valid.

### 7.5 Key Destruction

Keys are destroyed by:
1. **Secure memory zeroization:** Overwrite memory with zeros then random bytes. In managed runtimes, use mutable byte buffers and explicitly zero them. In Rust, use `zeroize` crate.
2. **Memory locking:** On desktop, use `mlock()` to prevent swapping to disk while keys are in RAM.
3. **Garbage collection awareness:** Explicitly zero byte arrays before dereferencing. Do NOT rely on GC.
4. **Platform secure element deletion:** Set key validity to session-based or use `destroyKey()`.

### 7.6 Lost Device

1. User acquires new device.
2. User enters master password on new device → derives KEK → decrypts VEK.
3. If user has encrypted backup: import backup, verify master password.
4. If user has recovery phrase: use phrase to derive KEK.
5. **Without any recovery material:** vault is unrecoverable. This is the honest cost of zero-knowledge.

### 7.7 Compromised Device

1. User detects device compromise.
2. User changes master password on a SAFE device.
3. New KEK + new VEK generated.
4. All records re-encrypted under new keys.
5. Old vault file cryptographically destroyed (overwrite with random data).
6. Paired devices revoked — attacker may have extracted pairing keys.
7. Recovery phrase regenerated.

---
