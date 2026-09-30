//! Error types for the vault-sdk crate.

/// Result type for vault-sdk operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by vault-sdk shared services.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// TOTP error (invalid secret, wrong code, clock drift).
    #[error("totp error: {0}")]
    Totp(String),

    /// Password generator error (invalid configuration).
    #[error("password error: {0}")]
    Password(String),

    /// Backup/restore error.
    #[error("backup error: {0}")]
    Backup(String),

    /// Recovery phrase error (invalid word, wrong length).
    #[error("recovery error: {0}")]
    Recovery(String),

    /// Other error.
    #[error("{0}")]
    Other(String),

    /// I/O error.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Other(s)
    }
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Other(s.to_string())
    }
}
