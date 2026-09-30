# Recovery Procedure

This document describes how to recover access to a Secret Manager vault when:

1. The master password has been forgotten.
2. The vault file is corrupted.
3. A user needs to be added or removed from a shared vault.

By design, Secret Manager **does not** have a master backdoor — there is no "factory reset" that bypasses the master password. Recovery is therefore only possible through one of the channels below.

## Recovery Channels (in priority order)

| Channel | Description | When to use |
|---|---|---|
| [Backup restore](#backup-restore) | Restore from a previously exported backup | Forgotten password, corrupted file |
| [Re-derive from password hint](#re-derive-from-password-hint) | Recall the password via hints | Forgotten password |
| [Sharing recovery](#sharing-recovery) | Decrypt via X25519 shared secret from a co-owner | Forgotten password, multi-party vault |
| [Manual reconstruction](#manual-reconstruction) | Last-resort debug-only via raw Argon2id derivation | Everything else |

## 1. Backup Restore

If you have a backup file (created via `secret-manager export`), this is the simplest recovery path.

### Requirements

- A valid export file (`.enc`).
- The **password that was active when the backup was created**.

> **Important:** The backup is itself encrypted with the VEK → KEK chain. If you have a backup but forgot the master password that was active when you made it, the backup is unusable. Backups do NOT bypass authentication.

### Procedure

```bash
# 1. Move (don't delete) the current vault file
mv ~/.config/secret-manager/vault.enc ~/.config/secret-manager/vault.enc.old

# 2. Point at the backup
export SECRET_MANAGER_VAULT=/path/to/backup.enc

# 3. Unlock with the password that was active at export time
secret-manager unlock

# 4. Verify records are present
secret-manager list

# 5. Export to the canonical vault location
secret-manager export > ~/.config/secret-manager/vault.enc

# 6. Restore the canonical path
unset SECRET_MANAGER_VAULT
secret-manager unlock  # should now work with the same password
```

### What if I forgot the password for the backup too?

Then the backup is as inaccessible as the original vault. There is no recovery from this state without the password. This is the deliberate security property — see "no backdoor" above.

## 2. Re-derive from Password Hint

Secret Manager does not store password hints in the vault file (they would be an attack vector). However:

- Check your personal password manager / note-taking app for hints.
- Check any "recovery question" notes you wrote down.
- Check if the password is in a printed emergency sheet in a safe.
- Check if the password follows a pattern you can reconstruct (e.g., a passphrase you remember the structure of).

### Trying candidate passwords safely

The library enforces a strict password validation floor — there is no rate-limiting. You can attempt as many passwords as you want.

```bash
# In a shell loop — each attempt takes ~250ms with default Argon2id params
for pw in candidate1 candidate2 "passphrase three" candidate4; do
  if secret-manager unlock <<< "$pw"; then
    echo "Found: $pw"
    break
  fi
done
```

**How fast can I brute-force?** With default parameters (m=65536, t=3, p=2), a typical desktop derives one KEK in ~250ms. At 4 attempts per second, a 6-character alphanumeric password has ~50 bits of entropy, taking ~10 years on average. Longer passphrases are practically unbreakable.

## 3. Sharing Recovery

Secret Manager supports an X25519 + Ed25519 sharing protocol. If a secret was shared with you, you can recover its DEK from a `ShareEnvelope` even if the original vault is gone.

### Procedure

```bash
# 1. Recover a single record from a share envelope
secret-manager recover --envelope envelope.json --sender <sender-pub-key>

# 2. The recovered record is added to your current unlocked vault
```

### Use cases

- A co-owner of a shared secret leaves the team. Their share remains valid.
- You rotate your master password but forget the new one. You can recover from a co-owner's share envelope.
- The vault file is destroyed but shares were distributed.

### Limitation

Sharing only recovers **records you were granted shares for**. The rest of the vault is unrecoverable.

## 4. Manual Reconstruction (Last Resort)

If everything else fails, you may still be able to reconstruct by brute-forcing the Argon2id derivation.

### When this is feasible

- Password is short or follows a known pattern (e.g., your birth year + initials).
- You have access to the salt (it's in the vault file header).
- You have very large compute resources (e.g., a GPU cluster).

### Procedure

1. Extract the salt:

   ```bash
   # Vault header is fixed 64 bytes for VLT1 format
   xxd -l 64 -s 0 ~/.config/secret-manager/vault.enc | head
   # Salt is at offset 12 (after magic, version, flags, reserved, kdf params, version length, version bytes)
   ```

2. Find or write an Argon2id brute-force tool that takes:
   - Salt (16 bytes from the header)
   - m_cost, t_cost, p_cost (also from the header)
   - A candidate password
   - And produces a 32-byte KEK.

3. For each candidate password, derive the KEK and try to decrypt the VEK wrap (bytes 28+N to 84+N of the header).

4. When decryption succeeds, you've found the password.

### Reference Argon2id brute-force script (Python)

```python
import argon2
import sys

salt = bytes.fromhex(sys.argv[1])
m_cost = int(sys.argv[2])
t_cost = int(sys.argv[3])
p_cost = int(sys.argv[4])
password = sys.argv[5].encode()

argon = argon2.PasswordHasher(
    time_cost=t_cost,
    memory_cost=m_cost,
    parallelism=p_cost,
    hash_len=32,
)
try:
    kek = argon.hash(password, salt=salt)
    print(kek)
except Exception as e:
    print(f"failed: {e}", file=sys.stderr)
```

> **Note:** The RustCrypto Argon2 implementation is the reference — any output from `argon2-cffi`, hashcat, or john must be byte-compatible. Verify with a known test vector first.

### GPU Acceleration

For serious brute-forcing, use [hashcat](https://hashcat.net/hashcat/) with mode `13600` (Argon2id). GPU-accelerated Argon2id can reach thousands of attempts per second on a single high-end GPU, but memory hardness limits parallelism.

### Legal Note

Only attempt this on vaults you own or have explicit authorization to access. Unauthorized access to encrypted data is a crime in most jurisdictions.

## Recovery Failure Scenarios

### "My vault file is corrupted"

1. **First** — try to open it. If `secret-manager unlock` succeeds, the corruption was transient.
2. **If HMAC fails** — the file was definitely modified. Restore from backup.
3. **If the file is unreadable at all** — the file may have been truncated or partially overwritten. Recovery is impossible without backup.

### "I see a panic on unlock"

Run with `RUST_BACKTRACE=1` for details. Common causes:

- **Wrong salt** — you restored from an export but used a different master password.
- **Wrong KDF params** — the header was corrupted. Restore from backup.
- **Encrypted record was modified** — the HMAC integrity check failed. Restore from backup.

### "Sharing envelope doesn't verify"

- The sender's signing key may have been rotated.
- The envelope may be from a different version of Secret Manager.
- The sender public key you have may be wrong.

## Prevention Checklist

Use this checklist to set up a recovery plan BEFORE you need one:

```
[ ] Create at least one backup and store it in a separate physical location
[ ] Choose a master password you can reconstruct from a printed emergency sheet
[ ] Print the emergency sheet and store it in a secure physical location (safe / deposit box)
[ ] For shared vaults: distribute shares to at least two trusted co-owners
[ ] Test your backup restore procedure at least once
[ ] Document your recovery plan in a secure location your family/trusted contacts can access
[ ] Set a calendar reminder to test backups annually
[ ] Verify your emergency sheet is still legible and up to date
```

## Emergency Sheet Template

```
EMERGENCY SHEET — SECRET MANAGER VAULT
========================================
Date prepared: ________________

Vault location: __________________________________
KDF parameters: m=<____> KiB, t=<__>, p=<__>
Vault salt (hex): ________________________________

Master password: ________________________________
                                         (write in pencil; do not leave exposed)

Backup location: ________________________________
Backup date: ___________________________________
Backup password: same as master password

Co-owner #1: ____________________________________
  Public key: ___________________________________
  Contact: _____________________________________

Co-owner #2: ____________________________________
  Public key: ___________________________________
  Contact: _____________________________________

Recovery procedure:
  1. ________________________________________
  2. ________________________________________
  3. ________________________________________
```

Keep this in a fireproof safe or safe deposit box. Do NOT store it alongside the vault file.

## What We Don't Recover

By design, Secret Manager cannot recover:

- A password that has been forgotten with no backup and no sharing setup.
- Data encrypted with a compromised key (in that case, generate a new password).
- Records that were explicitly deleted (the DEK is destroyed with the record).

If you cannot recover via the methods above, the data is permanently inaccessible. This is the intended security property.