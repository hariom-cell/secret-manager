//! Error types for the vault-db storage layer.

use vault_core::Error as VaultError;

/// Result type for vault-db operations.
pub type DbResult<T> = std::result::Result<T, DbError>;

/// Errors produced by the file-backed vault store.
#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// The vault is locked — operation requires unlock first.
    #[error("vault is locked")]
    VaultLocked,

    /// The vault file format is invalid or corrupt.
    #[error("invalid vault format: {0}")]
    InvalidFormat(String),

    /// Underlying vault-core error.
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),

    /// I/O error reading or writing the vault file.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    /// Internal invariant violated.
    #[error("internal error: {0}")]
    Internal(String),
}
