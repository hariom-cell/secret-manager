# Installation Guide

Three one-liners — pick your OS:

## macOS (Apple Silicon)

```bash
brew install hariomsehgal/secret-manager/secret-manager
```

## macOS (Intel) and any Linux

```bash
curl -fsSL https://install.secret-manager.dev | bash
```

That's it. The script detects your platform, downloads the right binary, and installs it to `/usr/local/bin`.

## Debian / Ubuntu

```bash
curl -fsSL https://apt.secret-manager.dev/setup.sh | sudo bash
```

Adds the official APT repo, then you can `sudo apt install secret-manager` and get automatic upgrades.

## Windows

Download the `.msi` from [GitHub Releases](https://github.com/hariomsehgal/secret-manager/releases).

Or with Scoop:

```bash
scoop bucket add hariomsehgal https://github.com/hariomsehgal/scoop-bucket
scoop install secret-manager
```

---

## What happens under the hood

The curl-pipe-bash script:
1. Detects your OS (`Darwin` / `Linux`) and architecture (`arm64` / `x86_64`)
2. Downloads the matching static binary from GitHub Releases
3. Installs it to `/usr/local/bin/secret-manager` (or `~/bin` if no sudo)
4. Creates `~/.config/secret-manager/` (mode 700) for the vault

No system services, no daemons, no auto-start. The CLI runs only when you invoke it.

---

## After install

```bash
secret-manager create        # Set master password, create vault
secret-manager unlock        # Decrypt vault into memory
secret-manager list          # List all record IDs
secret-manager get <id>      # Decrypt and print a secret
secret-manager set <id>      # Add or update a record
secret-manager delete <id>   # Remove a record
secret-manager lock          # Zeroize decrypted state
secret-manager export <file> # Save encrypted backup
secret-manager import <file> # Restore from backup
secret-manager gen-pass      # Generate strong password
```

## Verifying the install

```bash
secret-manager --version
# secret-manager 0.1.0
```

## Updating

```bash
# Homebrew
brew upgrade secret-manager

# APT
sudo apt update && sudo apt upgrade secret-manager

# Curl install
curl -fsSL https://install.secret-manager.dev | bash -s -- v0.2.0
```

## Uninstalling

```bash
# Homebrew
brew uninstall secret-manager

# APT
sudo apt remove secret-manager

# Curl install
sudo rm /usr/local/bin/secret-manager
```

Your encrypted vault file at `~/.config/secret-manager/vault.enc` is **not** deleted automatically. Back it up before uninstalling if you want to keep it.

---

## Build from source

Requires Rust 1.75+:

```bash
git clone https://github.com/hariomsehgal/secret-manager
cd secret-manager
cargo build --release --bin vault-cli
./target/release/vault-cli --help
```

## Build release binaries (all platforms)

```bash
./scripts/release.sh     # macOS + Linux
./scripts/build-deb.sh   # Debian package
```

## Cross-compile targets

```bash
rustup target add aarch64-apple-darwin
rustup target add x86_64-apple-darwin
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl
```