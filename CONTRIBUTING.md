# Contributing

Thank you for your interest in contributing to Secret Manager! This document describes the development workflow, code standards, and security rules for contributors.

## Quick Start

```bash
git clone https://github.com/your-org/secret-manager.git
cd secret-manager
cargo test                # Run all tests
cargo fmt -- --check      # Check formatting
cargo clippy --all-targets # Lint
```

## Prerequisites

- **Rust 1.75+** (MSRV tracked in CI)
- **SQLite CLI** (for manual DB inspection)
- **Git** (for signing commits — see below)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/). Be respectful. Report unacceptable behavior to the maintainers.

## How to Contribute

### Reporting Bugs

Open an issue with:

1. Rust version (`rustc --version`).
2. OS and version.
3. Minimal reproduction or steps to trigger.
4. Expected vs actual behavior.
5. `cargo test` output if relevant.

### Proposing Changes

1. Open an issue describing the change before you write code.
2. Fork the repo and create a feature branch from `main`.
3. Write tests alongside your changes.
4. Ensure `cargo fmt`, `cargo clippy`, and `cargo test` all pass.
5. Open a pull request with a clear description.

### Security Issues

**Do not file a public issue for security vulnerabilities.** See [SECURITY.md](SECURITY.md) for the vulnerability disclosure process.

## Code Standards

### Formatting

Run before committing:

```bash
cargo fmt
```

The CI rejects unformatted code. Configure your editor to format on save.

### Clippy

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

All warnings are denied in CI. Fix or explicitly allow with a justification comment.

### Tests

- **Unit tests** — colocated in the module, under `#[cfg(test)]`.
- **Integration tests** — in `crates/<crate>/tests/integration.rs`.
- **Fuzz tests** — in `fuzz/fuzz_targets/`. Run with `cargo run -p vault-fuzz --bin <name> -- 1000`.
- **Doc tests** — examples in `///` comments. Run with `cargo doc --no-deps --document-private-items`.

Every PR must include tests that cover the changed behavior.

### Commits

- Write clear, imperative commit messages.
- Reference issue numbers: `Fix: reject DEK wrap with wrong key (#42)`.
- Sign commits if your GPG key is configured:

```bash
git commit -S -m "feat: add platform key store trait"
```

- Squash before merging. Clean history over granularity.

## Architecture Principles

1. **`vault-core` has no I/O** — It is pure Rust with no filesystem, network, or OS dependencies. Platform-specific code lives in `vault-{linux,macos,android,windows}`.
2. **All secrets implement `ZeroizeOnDrop`** — Key material is scrubbed on drop. Don't bypass this.
3. **Constant-time comparisons** — Never use `==` to compare secrets (MACs, wrapped keys, hashes). Use `crate::utils::ct_eq`.
4. **No unwrap on secret paths** — Use `?` and return `Result`. In tests, use `.expect("message")` with a meaningful message.
5. **No secrets in logs** — Never log plaintext, key material, or passwords. Use `tracing::debug!` for non-sensitive flow info only.

## Dependency Policy

- Minimal dependency count — each new crate adds attack surface.
- Prefer crates from the RustCrypto org for crypto.
- Pin all crypto dependencies in `Cargo.lock` — never use a caret specifier on a crypto crate.
- Run `cargo audit` and `cargo deny check` before submitting a PR.

## CI Requirements

Every PR must pass:

| Check | Command |
|---|---|
| Formatting | `cargo fmt -- --check` |
| Lint | `cargo clippy --all-targets -- -D warnings` |
| Tests | `cargo test --all-targets` |
| Security audit | `cargo audit` |
| License check | `cargo deny check licenses` |
| Fuzz | `cargo run -p vault-fuzz --bin fuzz_format_parse -- 1000 && cargo run -p vault-fuzz --bin fuzz_aead_roundtrip -- 1000` |

## Review Process

1. **Automated checks** must pass (see above).
2. **At least one maintainer** must approve.
3. For changes touching `vault-core`, a second review from a maintainer is required if the PR touches:
   - Crypto primitives (`aead`, `kdf`, `dek`, `vek`, `format`, `integrity`).
   - Key hierarchy or envelope encryption flow.
   - `Zeroize` / memory safety guarantees.

## Release Process

1. Maintainers bump the version in `Cargo.toml` files.
2. `cargo-release` is used for changelog generation.
3. A GitHub Release is created with signed artifacts (see `scripts/release.sh`).
4. The release is announced with a summary of changes.

## Getting Help

- **Issues:** https://github.com/your-org/secret-manager/issues
- **Discussions:** https://github.com/your-org/secret-manager/discussions

Thank you for making Secret Manager better.