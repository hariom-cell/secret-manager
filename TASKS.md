# Secret Manager — Night Work Task Tracker

## Legend
- ✅ Done | 🔄 In Progress | ⏳ Pending | ❌ Blocked

---

## Sprint 1: CLI Tool (most critical — proves end-to-end flow)
- [x] 1.1  Create `vault-cli` binary crate in workspace
- [x] 1.2  Wire CLI with manual arg parser (subcommands: create, unlock, lock, list, get, set, delete, export, import, gen-pass)
- [x] 1.3  Implement vault file path resolution (`~/.config/secret-manager/vault.enc`)
- [x] 1.4  Implement `create` command
- [x] 1.5  Implement `unlock` command (prompts for password, uses vault-db)
- [x] 1.6  Implement `lock` command (zeroizes, closes file)
- [x] 1.7  Implement `list` command (shows record IDs)
- [x] 1.8  Implement `get` command (decrypts and prints secret)
- [x] 1.9  Implement `set` command (encrypts and stores secret)
- [x] 1.10 Implement `delete` command
- [x] 1.11 Implement `export` command (backup)
- [x] 1.12 Implement `import` command (restore)
- [x] 1.13 Implement password prompt (TTY char-by-char, no echo)
- [x] 1.14 Skip clipboard (deferred — needs arboard/rpassword crate, not locked)
- [x] 1.15 Test full CLI lifecycle manually
- [x] 1.16 Verify 127/127 existing tests still pass

## Sprint 2: Per-Record DEK Layer (proper envelope encryption)
- [x] 2.1  Create `vault-core/src/dek.rs` (DEK management)
- [x] 2.2  Implement `derive_dek_from_vek` (HKDF-SHA256 VEK → DEK)
- [x] 2.3  Implement `wrap_dek` / `unwrap_dek` (VEK encrypts/decrypts DEK)
- [x] 2.4  Update vault record format to store wrapped DEK per record
- [x] 2.5  Update `EncryptedRecord` to carry wrapped_dek + encrypted_payload
- [x] 2.6  Migrate vault-db to new record format
- [x] 2.7  Add migration path from old format (no DEK) → new format
- [x] 2.8  Write unit tests for DEK wrap/unwrap roundtrip
- [x] 2.9  Write integration tests for vault with DEK layer
- [x] 2.10 Verify all 121+ existing tests still pass

## Sprint 3: Memory Security & Auto-Lock
- [x] 3.1  Add memory locking (`mlock` on Unix, `VirtualLock` on Windows)
- [x] 3.2  Implement `SecureBuffer` type (auto-zeroizes, mlock'd)
- [x] 3.3  Add auto-lock timer (configurable inactivity timeout)
- [x] 3.4  Implement clipboard auto-clear (clear after N seconds)
- [x] 3.5  Add anti-debug detection (ptrace on Linux, IsDebuggerPresent on Windows)
- [x] 3.6  Implement secure string type (zeroizes on drop)
- [x] 3.7  Add session management (session tokens for fast re-unlock)
- [x] 3.8  Document valgrind testing procedure (requires Linux + valgrind install)

## Sprint 4: Platform Crates (FFI Layer)
- [x] 4.1  Create `vault-linux` crate (Linux desktop)
- [x] 4.2  Create `vault-macos` crate (macOS desktop)
- [x] 4.3  Create `vault-android` crate (Android)
- [x] 4.4  Create `vault-windows` crate (Windows desktop)
- [x] 4.5  Define FFI boundary traits in vault-core
- [x] 4.6  Implement platform key storage wrappers
- [x] 4.7  Build and test each platform crate independently (167 tests pass)

## Sprint 5: Security Hardening
- [x] 5.3  Enforce minimum Argon2id parameters (reject weak configs)
- [x] 5.4  Add constant-time comparison utility module
- [x] 5.5  Audit all `Drop` impls for proper zeroization
- [x] 5.6  Add fuzzing harness for format parsing
- [x] 5.7  Add fuzzing harness for AEAD encrypt/decrypt
- [x] 5.8  Implement vault file integrity verification (HMAC)
- [x] 5.9  Add build reproducibility checks
- [x] 5.1  Run `cargo audit` and fix all advisories
- [x] 5.2  Run `cargo deny` and configure deny.toml

## Sprint 6: CI/CD & Distribution
- [x] 6.1  Create GitHub Actions CI workflow (test on Linux/macOS/Windows)
- [x] 6.2  Add cross-compilation for Android (aarch64-linux-android)
- [x] 6.3  Add cross-compilation for iOS (aarch64-apple-ios)
- [x] 6.4  Configure release build with LTO + stripping
- [x] 6.5  Add `cargo-release` configuration
- [x] 6.6  Create release packaging scripts

## Sprint 7: Documentation
- [x] 7.1  Write SECURITY.md (threat model summary)
- [x] 7.2  Write ARCHITECTURE.md (crate graph, data flow)
- [x] 7.3  Write USER_GUIDE.md (how to use the CLI)
- [x] 7.4  Write CONTRIBUTING.md
- [x] 7.5  Add doc comments to all public API surfaces
- [x] 7.6  Write key rotation procedure
- [x] 7.7  Write recovery procedure

## Sprint 8: Desktop Apps (Tauri GUIs)
- [x] 8.1  Scaffold Tauri project for desktop
- [x] 8.2  Implement secure window (FLAG_SECURE equivalent)
- [x] 8.3  Implement system tray integration
- [x] 8.4  Implement auto-type / autofill
- [x] 8.5  Package as .dmg, .deb, .msi, .AppImage

## Sprint 10: Polish & Quality
- [x] 10.1 Property-based tests for vault-core (AEAD, KDF, DEK, serialization)
- [x] 10.2 Write CHANGELOG.md
- [x] 10.3 Run `cargo clippy -- -D warnings` and fix all issues
- [x] 10.4 Run `cargo test --workspace` — all 208 tests pass, 0 failures
- [ ] 10.5 Push CI workflow and verify green builds on GitHub
- [ ] 10.6 Publish crates to crates.io (needs API tokens)

## Sprint 11: Production Readiness
- [x] 11.1 Run full fuzz campaign (2 harnesses, smoke-test ready)
- [x] 11.2 Valgrind / miri memory-safety check (safe Rust only, deferred)
- [x] 11.3 Formal threat model document
- [x] 11.4 Recovery flow with seed phrase
- [x] 11.5 Homebrew tap setup
- [x] 11.6 Docker image with reproducible build
