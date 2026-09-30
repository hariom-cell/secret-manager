//! Vault Core — cryptographic primitives for the Secret Manager.
//!
//! This crate implements the key hierarchy and authenticated encryption
//! described in the architecture document. Every type that holds key material
//! implements [`Zeroize`] and [`ZeroizeOnDrop`] so bytes are scrubbed on drop.
//!
//! # Crate Status
//!
//! Step 2 — KDF added. Now provides:
//! - [`KeyBytes`]: 256-bit key container with secure erasure on drop
//! - [`aead`]: XChaCha20-Poly1305 (RFC 8439) encrypt/decrypt
//! - [`kdf`]: Argon2id (RFC 9106) master password → KEK
//!
//! Subsequent steps will add:
//! - VEK wrap/unwrap under KEK
//! - Per-record DEK derivation (HKDF-SHA256)
//! - Sharing protocol (X25519 + Ed25519)
//! - Vault file format

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod aead;
pub mod clipboard;
pub mod crypto;
pub mod dek;
pub mod error;
pub mod ffi;
pub mod format;
pub mod integrity;
pub mod kdf;
pub mod memory;
pub mod session;
pub mod sharing;
pub mod types;
pub mod vault;
pub mod vek;

// Re-exports for ergonomics
pub use aead::{decrypt_record, encrypt_record, Ciphertext, Nonce, NONCE_SIZE, TAG_SIZE};
pub use clipboard::{
    AutoClearClipboard, AutoClearClipboardArc, ClipboardAutoClear, ClipboardBackend,
    ClipboardError, MockClipboard, NoopClipboard,
};
pub use dek::{derive_dek, random_dek, unwrap_dek, wrap_dek, RecordKey, WrappedDek};
pub use error::{Error, Result};
pub use ffi::{KeyStore, Platform, SecureInput, SessionPersistence, SystemClipboard};
pub use format::{read_vault, write_vault, deserialize_records, serialize_records, parse_header, serialize_header, HEADER_SIZE, VAULT_MAGIC};
pub use kdf::{derive_kek, KdfParams};
pub use memory::{lock_all, lock_bytes, AutoLock, SecureBuffer, SecureString};
pub use session::{SessionError, SessionManager, SessionToken};
pub use sharing::{recover_dek, share_dek, ReceiverPublicKey, SenderSigningKey, SenderVerifyingKey, ShareEnvelope};
pub use types::KeyBytes;
pub use vault::{EncryptedRecord, RecordId, Vault};
pub use vek::{Vek, WrappedVek};
