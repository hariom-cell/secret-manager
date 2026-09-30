//! Shared services for the Secret Manager.
//!
//! This crate bundles higher-level functionality on top of `vault-core` and
//! `vault-db`:
//!
//! - [`password`]: cryptographically secure password generator
//! - [`totp`]: RFC 6238 Time-based One-Time Passwords (HMAC-SHA256)
//! - [`recovery`]: mnemonic recovery phrases

pub mod backup;
pub mod error;
pub mod password;
pub mod recovery;
pub mod totp;

pub use error::{Error, Result};
