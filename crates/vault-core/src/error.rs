//! Error types for the vault-core crate.

use thiserror::Error;

/// Result type alias for vault-core operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum Error {
    /// Key derivation failed (Argon2 error).
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    /// Encryption/decryption routine returned an unexpected error.
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    /// The provided key length is invalid.
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength {
        /// Expected key length in bytes.
        expected: usize,
        /// Actual key length received.
        got: usize,
    },

    /// A ciphertext blob is too short to be valid.
    #[error("ciphertext too short: minimum {min} bytes, got {got}")]
    CiphertextTooShort {
        /// Minimum required length in bytes.
        min: usize,
        /// Actual length received.
        got: usize,
    },

    /// AEAD tag mismatch — wrong key, tampered ciphertext, or wrong password.
    ///
    /// The same error is returned in all three cases so an attacker cannot
    /// distinguish "wrong password" from "tampered ciphertext" via timing
    /// or error messaging.
    #[error("authentication failed")]
    AuthenticationFailed,

    /// Vault file integrity check failed — the HMAC tag did not verify.
    ///
    /// The file has been tampered with or corrupted. The same error is
    /// returned regardless of which part of the header was altered.
    #[error("vault file integrity check failed")]
    IntegrityFailed,

    /// An internal invariant was violated (should never occur in production).
    #[error("internal error: {0}")]
    Internal(String),

    /// Serialization/deserialization error (IO or format violation).
    #[error("encoding error: {0}")]
    Encoding(String),

    /// Storage / I/O error (file system, keychain, etc.).
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Storage(e.to_string())
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::Storage(e.to_string())
    }
}
