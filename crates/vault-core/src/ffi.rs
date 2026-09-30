//! FFI boundary traits — the abstraction layer between `vault-core`
//! and platform-specific code.
//!
//! Each platform crate (`vault-linux`, `vault-macos`, `vault-android`,
//! `vault-windows`) implements these traits using native APIs.  The
//! cryptographic core (`vault-core`) depends only on these traits,
//! not on any platform code.
//!
//! # Why traits, not direct calls?
//!
//! - **Testability**: unit tests provide mock implementations.
//! - **Zero-cost abstraction**: the compiler inlines trait methods
//!   when the concrete type is known.
//! - **Separation of concerns**: the crypto crate stays pure Rust,
//!   no FFI, no platform SDKs.

use std::sync::Arc;

use crate::Result;
use crate::session::SessionToken;

// ─── Key Storage ────────────────────────────────────────────────────────

/// A secure storage backend for cryptographic keys.
///
/// Platform implementations store keys in the OS keychain or secure
/// hardware enclave (e.g. TPM, Secure Enclave, Keystore).
pub trait KeyStore: Send + Sync {
    /// Store a named secret (e.g. an Argon2id salt or a session key).
    fn store(&self, name: &str, data: &[u8]) -> Result<()>;

    /// Retrieve a named secret.
    fn retrieve(&self, name: &str) -> Result<Vec<u8>>;

    /// Delete a named secret.
    fn delete(&self, name: &str) -> Result<()>;

    /// Check whether a named secret exists.
    fn contains(&self, name: &str) -> bool;
}

// ─── Secure Input ──────────────────────────────────────────────────────

/// Secure password input (no echo, no clipboard leak).
pub trait SecureInput: Send + Sync {
    /// Prompt for a password interactively.
    fn prompt_password(&self, prompt: &str) -> Result<String>;

    /// Prompt for confirmation (return true on match).
    fn confirm_password(&self, prompt: &str, expected: &str) -> Result<bool>;
}

// ─── Clipboard ─────────────────────────────────────────────────────────

/// System clipboard access (copy / paste).
pub trait SystemClipboard: Send + Sync {
    /// Copy text to the system clipboard.
    fn copy(&self, text: &str) -> Result<()>;

    /// Paste text from the system clipboard.
    fn paste(&self) -> Result<String>;

    /// Clear the system clipboard.
    fn clear(&self) -> Result<()>;
}

// ─── Session Persistence ───────────────────────────────────────────────

/// Persist / retrieve session tokens from the OS keychain.
pub trait SessionPersistence: Send + Sync {
    /// Save a session token under a service/account pair.
    fn save_token(&self, service: &str, account: &str, token: &SessionToken) -> Result<()>;

    /// Load a saved session token.
    fn load_token(&self, service: &str, account: &str) -> Result<Option<SessionToken>>;

    /// Delete a saved session token.
    fn delete_token(&self, service: &str, account: &str) -> Result<()>;
}

// ─── Unified Platform Abstraction ──────────────────────────────────────

/// Top-level platform abstraction that bundles all OS services.
pub trait Platform {
    /// Key storage backend.
    fn key_store(&self) -> Arc<dyn KeyStore>;
    /// Secure input backend.
    fn secure_input(&self) -> Arc<dyn SecureInput>;
    /// Clipboard backend.
    fn clipboard(&self) -> Arc<dyn SystemClipboard>;
    /// Session persistence backend.
    fn session_persistence(&self) -> Arc<dyn SessionPersistence>;
}
