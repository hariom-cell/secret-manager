# User Guide

A practical guide to using Secret Manager. It is assumed you have already installed the `secret-manager` CLI.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Commands](#commands)
3. [Workflows](#workflows)
4. [Frequently Asked Questions](#frequently-asked-questions)

## Getting Started

### Create a new vault

```bash
secret-manager create
```

You will be prompted for a **master password**. Choose something long and memorable — or generate one:

```bash
secret-manager gen-pass --length 32
```

The vault file is created at `~/.config/secret-manager/vault.enc` by default. Override with the `SECRET_MANAGER_VAULT` environment variable:

```bash
export SECRET_MANAGER_VAULT=/secure/path/vault.enc
```

### Unlock the vault

```bash
secret-manager unlock
```

You will be prompted for your master password. While unlocked you can run `get`, `set`, `list`, and `delete`. The vault auto-locks after a period of inactivity (default 15 minutes).

## Commands

### `create`

Create a new vault. Fails if the vault file already exists.

```bash
secret-manager create
```

### `unlock`

Decrypt and load the vault into memory.

```bash
secret-manager unlock
```

### `lock`

Zeroize all keys in memory and close the vault file.

```bash
secret-manager lock
```

### `list`

Print the IDs of all stored secrets.

```bash
secret-manager list
```

### `get`

Decrypt and print a secret's value to stdout.

```bash
secret-manager get <record_id>
```

**Tip:** Pipe into a clipboard tool:

```bash
secret-manager get github-pat | xclip -selection clipboard
```

### `set`

Encrypt and store a secret value.

```bash
secret-manager set <record_id>
```

You will be prompted to type the secret value. It is not echoed.

Alternatively, pipe from stdin:

```bash
echo "my secret value" | secret-manager set my-key
```

### `delete`

Permanently remove a secret.

```bash
secret-manager delete <record_id>
```

**Warning:** This is irreversible. The DEK is also discarded, making recovery impossible even with the master password.

### `export`

Export the entire vault as a portable encrypted file (signed with your Ed25519 signing key).

```bash
secret-manager export > backup.vault.enc
```

### `import`

Restore secrets from an exported file.

```bash
secret-manager import < backup.vault.enc
```

### `gen-pass`

Generate a cryptographically random password.

```bash
secret-manager gen-pass --length 24
secret-manager gen-pass --length 64 --no-symbols
```

Options:

| Flag | Default | Description |
|---|---|---|
| `--length` / `-l` | 24 | Number of characters |
| `--no-symbols` | off | Exclude non-alphanumeric characters |

## Workflows

### Daily use

1. `unlock` — enter master password.
2. `get` / `set` / `list` — work with secrets.
3. `lock` — explicitly lock when done (or rely on auto-lock).

### Backing up

```bash
# Create a dated backup
secret-manager export > ~/backups/vault-$(date +%Y-%m-%d).enc

# Restore from backup
secret-manager import < ~/backups/vault-2025-09-29.enc
```

Store backups in a separate location from the vault file (different disk, encrypted cloud storage, etc.).

### Changing the master password

Key rotation requires unlocking with the current password, then re-creating the vault:

```bash
secret-manager export > /tmp/backup.enc
secret-manager lock
# Rename old vault
mv ~/.config/secret-manager/vault.enc ~/.config/secret-manager/vault.enc.bak
# Re-create with new password
secret-manager create
secret-manager import < /tmp/backup.enc
secret-manager delete <re-enter any secrets whose keys you want to rotate>
rm ~/.config/secret-manager/vault.enc.bak
```

**Why the manual dance?** Because the VEK is wrapped under the KEK — changing the password requires unwrapping the old VEK and re-wrapping under a new KEK. This will be automated in a future release.

### Using with CI/CD

Export a single secret and inject it into the pipeline:

```bash
# Local: export one record
secret-manager get api-key > /tmp/api-key

# CI: read from file or env
API_KEY=$(cat /tmp/api-key)
```

For automation, use the Rust API directly (see `vault-sdk` docs) instead of the CLI.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_MANAGER_VAULT` | `~/.config/secret-manager/vault.enc` | Path to the vault file |
| `SECRET_MANAGER_TIMEOUT` | `900` (15 min) | Auto-lock timeout in seconds |
| `SECRET_MANAGER_CLIPBOARD_TTL` | `30` | Clipboard auto-clear in seconds |

## Security Tips

1. **Use a strong master password.** Generate one with `gen-pass` and store it in a physically separate location (e.g., a safety deposit box or password manager outside this vault).
2. **Enable auto-lock.** The default 15-minute timeout is a good baseline.
3. **Back up regularly.** Export the vault and store the backup separately.
4. **Verify your environment.** The anti-debug check will warn you if a debugger is attached. Don't unlock in an environment you don't trust.
5. **Never commit the vault file.** Add `vault.enc` and backups to `.gitignore`.

## Frequently Asked Questions

**Q: Is this a replacement for 1Password / Bitwarden?**

Secret Manager is a **library** (with a CLI for testing). It provides the cryptographic building blocks for a production password manager but is not yet feature-complete compared to a commercial product. Use it as the core of a custom solution.

**Q: What happens if I forget my master password?**

There is no backdoor or recovery mechanism built in (by design). You can recover from a backup if you have one. We are working on Shamir's Secret Sharing for social recovery.

**Q: Can I use this on my phone?**

Android and iOS platform crates are included in the workspace. They are not yet packaged as apps — see Sprint 8.

**Q: Is the vault format versioned?**

Yes. The header includes a `FORMAT_VERSION` byte. The parser rejects unknown versions and refuses to open the vault.

**Q: Why Argon2id over bcrypt / scrypt?**

Argon2id is the PHC winner and the current OWASP recommendation for password hashing. It provides configurable memory hardness which makes GPU/ASIC attacks expensive.

**Q: Why XChaCha20-Poly1305 over AES-GCM?**

- Hardware-accelerated on all modern CPUs via AVX2/NEON.
- 192-bit nonces (vs 96-bit for GCM) eliminate nonce-collision risk.
- No timing side channels in software implementations.
- Better audited than AES-GCM in Rust (single RustCrypto crate, no external C libs).

**Q: How do I contribute?**

See [CONTRIBUTING.md](CONTRIBUTING.md).