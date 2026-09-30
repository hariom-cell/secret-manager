# Key Rotation Procedure

This document describes how to rotate the master password (and therefore the KEK) for a Secret Manager vault.

## Background

Secret Manager uses a three-layer key hierarchy (see [SECURITY.md](SECURITY.md)):

- **KEK** (Key Encryption Key) — derived from the master password via Argon2id. Used to wrap the VEK.
- **VEK** (Vault Encryption Key) — random 256-bit key that encrypts all records. Wrapped under the KEK for storage.
- **DEK** (Data Encryption Key) — per-record keys derived via HKDF-SHA256 from the VEK.

Changing the master password requires:

1. Unwrapping the VEK with the old KEK.
2. Deriving a new KEK from the new password.
3. Re-wrapping the VEK under the new KEK.

**DEKs are never stored** — they are re-derived from the VEK + record_id, so no re-encryption of individual records is needed.

## Manual Rotation (CLI)

> **Note:** An automated `rotate-password` command is planned for a future release. Until then, use the manual procedure below.

### Step 1: Export the vault

```bash
# Export the vault while unlocked
secret-manager export > /tmp/vault-backup-$(date +%Y%m%d).enc
```

Verify the export succeeded:

```bash
wc -c /tmp/vault-backup-$(date +%Y%m%d).enc
# Should be non-zero
```

### Step 2: Lock and verify backup

```bash
secret-manager lock

# Verify the vault file still exists
ls -la ~/.config/secret-manager/vault.enc

# Verify the backup can be imported into a fresh vault (optional but recommended)
export SECRET_MANAGER_VAULT=/tmp/test-rotate-vault.enc
secret-manager create --password test
secret-manager import < /tmp/vault-backup-$(date +%Y%m%d).enc
secret-manager list   # Should show all your records
rm /tmp/test-rotate-vault.enc
```

### Step 3: Create a new vault with the new password

```bash
# Rename the old vault as a safety net
mv ~/.config/secret-manager/vault.enc ~/.config/secret-manager/vault.enc.bak

# Create a new vault with the new password
export SECRET_MANAGER_VAULT=~/.config/secret-manager/vault.enc
secret-manager create
# Enter your NEW master password
```

### Step 4: Import records

```bash
secret-manager import < /tmp/vault-backup-$(date +%Y%m%d).enc
```

All records are now accessible under the new password.

### Step 5: Clean up

```bash
# Verify the new vault works
secret-manager list
secret-manager get <some-record>

# Securely delete the backup and old vault
shred -u /tmp/vault-backup-$(date +%Y%m%d).enc
shred -u ~/.config/secret-manager/vault.enc.bak
```

> **Tip:** On macOS, use `srm` instead of `shred`. On systems without `shred`, overwrite with random data first.

## Rotation via SDK (Programmatic)

```rust
use vault_sdk::{VaultManager, VaultManagerConfig};

// 1. Unlock the existing vault
let mut manager = VaultManager::open(Config::default()).await?;
manager.unlock("old-password").await?;

// 2. Export to a portable format
let backup = manager.export().await?;
manager.lock().await?;

// 3. Create new vault manager (creates new file)
let new_manager = VaultManager::create(Config::default()).await?;

// 4. Import
new_manager.import(&backup).await?;

// 5. The old vault file can now be securely deleted
```

## When to Rotate

| Situation | Recommended Action |
|---|---|
| Employee departure | Rotate immediately |
| Suspected master password exposure | Rotate immediately |
| Scheduled rotation policy | Rotate per policy (e.g., every 90 days) |
| Device compromise | Rotate + consider wiping all vaults |
| Long-term shared vault | Rotate whenever a participant leaves |

## Rotation Checklist

```
[ ] Export vault to encrypted backup file
[ ] Store backup in a separate location (different disk)
[ ] Create new vault with new password
[ ] Import backup into new vault
[ ] Verify all records are present (secret-manager list)
[ ] Spot-check critical records (secret-manager get <id>)
[ ] Securely delete old vault file
[ ] Securely delete backup file
[ ] Update password manager / safe deposit box with new password
[ ] Notify any sharing recipients that a new share will be needed
```

## What Changes After Rotation

| Component | Action |
|---|---|
| Vault salt | New random salt generated |
| Argon2id parameters | Same (stored in header of new file) |
| VEK | Same (unwrapped from old KEK, re-wrapped under new KEK) |
| DEKs | Unchanged (derived from VEK, not KEK) |
| Record ciphertexts | Unchanged |
| HMAC | Recomputed over new header |
| Sharing envelopes | Unchanged (DEK hasn't changed) |

## What Does NOT Change

- **Individual record data** — no re-encryption needed.
- **DEK wrapping keys** — same VEK, same DEKs.
- **Shared secrets** — sharing envelopes remain valid.

## Recovery After a Failed Rotation

If something goes wrong during rotation:

1. The old vault file (`vault.enc.bak`) still contains the old data.
2. The export backup (`vault-backup-*.enc`) contains a portable copy.
3. Unlock the backup:

   ```bash
   export SECRET_MANAGER_VAULT=/tmp/vault-backup-<date>.enc
   secret-manager unlock
   ```

4. If the old vault was encrypted with a different KDF (e.g., you manually edited the header), specify it explicitly:

   ```bash
   secret-manager unlock --salt <hex> --m-cost 65536 --t-cost 3 --p-cost 2
   ```

5. Re-export and retry the rotation.

## Automated Rotation (Future)

A planned `secret-manager rotate` command will:

1. Prompt for old password.
2. Derive new KEK from a freshly generated password (or user-supplied).
3. Re-wrap the VEK.
4. Write the updated header in-place.
5. Verify with a round-trip decryption check.

This eliminates the export/import dance. Until then, the manual procedure above is the supported path.