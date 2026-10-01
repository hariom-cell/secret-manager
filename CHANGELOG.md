# Changelog

All notable changes to Secret Manager are documented here. The format is based on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Property-based tests for AEAD, KDF, DEK, and serialization (`proptest`)

### Changed
- All workspace path dependencies now pinned with `version = "0.1.0"`

### Security
- `cargo audit` — zero vulnerabilities
- `cargo deny` — all four checks pass (advisories, bans, licenses, sources)

---

## [0.1.0] — 2025-10-01

### Added — Core Cryptography (vault-core)
- XChaCha20-Poly1305 AEAD with 192-bit random nonces
- Argon2id KDF with configurable memory/time/parallelism cost parameters
- Envelope encryption: KEK (master password) wraps VEK, VEK derives per-record DEKs via HKDF-SHA256
- HMAC-SHA256 integrity verification on vault file headers
- `SecureBuffer` / `SecureString` with `mlock()` on Unix and `VirtualLock` on Windows
- Constant-time comparison utility for all security-critical equality checks
- Auto-lock with configurable inactivity timeout
- Anti-debug detection (ptrace on Linux, `IsDebuggerPresent` on Windows)
- Session tokens with TTL for fast re-unlock
- Clipboard auto-clear after configurable timeout

### Added — CLI (vault-cli)
- Full CRUD: create, unlock, lock, list, get, set, delete
- Vault export/import (backup and restore)
- Password generation with configurable policies (length, character classes)
- TOTP code generation and validation
- One-line install script for macOS (ARM + Intel) and Linux

### Added — File Storage (vault-db)
- Binary vault file format with 256-byte header
- Vault lifecycle: create, open, unlock, lock, close
- Record CRUD with per-record DEK encryption
- Tamper detection (HMAC verification on unlock)
- Format validation (magic bytes, minimum size)
- Persistence across lock/unlock cycles

### Added — Platform Crates
- `vault-linux` — Linux desktop FFI bindings
- `vault-macos` — macOS desktop FFI bindings
- `vault-android` — Android NDK FFI bindings
- `vault-windows` — Windows FFI bindings
- Memory locking, secure string, clipboard primitives per platform

### Added — WASM / Web (vault-wasm)
- WASM bindings exposing vault operations to JavaScript
- In-memory vault state (no filesystem access from WASM)
- Re-exports password policy and TOTP types for JS consumers

### Added — Desktop GUI (Tauri)
- System tray integration
- Secure window (FLAG_SECURE equivalent)
- Auto-type / autofill support
- Packaging targets: `.dmg`, `.deb`, `.msi`, `.AppImage`

### Added — Fuzzing
- Format parsing fuzz harness
- AEAD encrypt/decrypt fuzz harness

### Added — CI/CD
- GitHub Actions matrix: Linux (Ubuntu), macOS, Windows
- Cross-compilation for Android (aarch64-linux-android) and iOS (aarch64-apple-ios)
- `cargo-release` configuration for automated versioning

### Added — Documentation
- `SECURITY.md` — threat model summary
- `ARCHITECTURE.md` — crate graph and data flow diagrams
- `USER_GUIDE.md` — CLI usage instructions
- `CONTRIBUTING.md` — contributor guidelines
- Key rotation procedure
- Recovery procedure
- Doc comments on all public API surfaces

### Security
- Per-record DEK layer (envelope encryption)
- All sensitive buffers zeroized on drop (`zeroize` crate)
- All `Drop` impls audited for proper zeroization
- Minimum Argon2id parameters enforced
- `cargo audit` and `cargo deny` configured with strict policies
- AGPL-3.0-or-later license

[Unreleased]: https://github.com/hariom-cell/secret-manager/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hariom-cell/secret-manager/releases/tag/v0.1.0
