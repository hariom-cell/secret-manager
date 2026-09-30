//! Vault Encryption Key (VEK) — the key that encrypts all DEKs in the vault.
//!
//! ## Key Hierarchy
//!
//! ```text
//! Master Password → Argon2id → KEK → wraps → VEK → unwraps → DEK
//! ```
//!
//! The VEK is a random 256-bit key generated once per vault creation. It is
//! never stored in plaintext — only as a [`WrappedVek`] (encrypted under the KEK).
//! Each time the vault is unlocked, a fresh KEK is derived and used to unwrap
//! the VEK. The VEK then derives per-record DEKs via HKDF-SHA256.

use crate::{
    aead::{decrypt_record, encrypt_record, Ciphertext},
    error::Result,
    types::KeyBytes,
};
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A vault-wide encryption key. Generated once at vault creation, wrapped under
/// the KEK, and stored in the vault file header. On unlock, the KEK unwraps
/// it back to this type.
///
/// The VEK is the root of per-record key derivation — every [`RecordKey`] is
/// `HKDF-SHA256(VEK, record_id)`.
///
/// Implements [`ZeroizeOnDrop`] — the key bytes are scrubbed when dropped.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Vek {
    inner: KeyBytes,
}

impl Vek {
    /// Generate a new random VEK. Called during vault creation only.
    ///
    /// Uses the OS CSPRNG (`getrandom`). The returned key is random and
    /// suitable for immediate use.
    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self { inner: KeyBytes::new(bytes) }
    }

    /// Construct a VEK from raw bytes. Useful for deserialization and tests.
    ///
    /// # Safety
    ///
    /// The caller must ensure `bytes` is truly random and was not exposed
    /// before. In normal operation, prefer [`Vek::random`] or
    /// [`WrappedVek::unwrap`].
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { inner: KeyBytes::new(bytes) }
    }

    /// Borrow the underlying key material.
    ///
    /// Most callers should use higher-level APIs (e.g. [`derive_dek`]) rather
    /// than handling raw bytes.
    pub fn as_key_bytes(&self) -> &KeyBytes {
        &self.inner
    }

    /// Wrap (encrypt) this VEK under the KEK for safe storage in the vault
    /// file header.
    ///
    /// Each call produces a different ciphertext (random nonce) even with the
    /// same KEK.
    pub fn wrap(&self, kek: &KeyBytes) -> Result<WrappedVek> {
        let ciphertext = encrypt_record(kek, self.inner.as_bytes())?;
        Ok(WrappedVek { ciphertext })
    }
}

/// A VEK encrypted under a KEK — the only form stored in the vault file.
///
/// # Serialization
///
/// `WrappedVek` serializes to `nonce || ciphertext || tag`, which is exactly
/// what the vault file header stores at offset 28+N (after MAGIC, VERSION,
/// FLAGS, reserved, KDF params, VERSION_LEN, VERSION, SALT, and VEK_NONCE).
///
/// See [`WrappedVek::to_bytes`] and [`WrappedVek::from_bytes`] for I/O.
#[derive(Debug, Clone)]
pub struct WrappedVek {
    ciphertext: Ciphertext,
}

impl WrappedVek {
    /// Serialize for storage: nonce || ciphertext.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.ciphertext.to_bytes()
    }

    /// Deserialize from stored bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self { ciphertext: Ciphertext::from_bytes(bytes)? })
    }

    /// Unwrap with the KEK to recover the VEK.
    pub fn unwrap(&self, kek: &KeyBytes) -> Result<Vek> {
        let mut plaintext = decrypt_record(kek, &self.ciphertext)?;
        if plaintext.len() != 32 {
            return Err(crate::Error::InvalidKeyLength { expected: 32, got: plaintext.len() });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(Vek { inner: KeyBytes::new(bytes) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_key() -> KeyBytes {
        let mut b = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut b);
        KeyBytes::new(b)
    }

    #[test]
    fn random_vek_is_32_bytes() {
        assert_eq!(Vek::random().as_key_bytes().as_bytes().len(), 32);
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let vek = Vek::random();
        let kek = random_key();
        let wrapped = vek.wrap(&kek).unwrap();
        let unwrapped = wrapped.unwrap(&kek).unwrap();
        assert_eq!(unwrapped.as_key_bytes().as_bytes(), vek.as_key_bytes().as_bytes());
    }

    #[test]
    fn wrap_unwrap_with_same_kek_different_nonces() {
        let vek = Vek::random();
        let kek = random_key();
        let w1 = vek.wrap(&kek).unwrap();
        let w2 = vek.wrap(&kek).unwrap();
        assert_ne!(w1.to_bytes(), w2.to_bytes(), "different nonces → different ciphertexts");
    }

    #[test]
    fn wrong_kek_fails_unwrap() {
        let vek = Vek::random();
        let kek = random_key();
        let wrong = random_key();
        let wrapped = vek.wrap(&kek).unwrap();
        assert!(matches!(
            wrapped.unwrap(&wrong),
            Err(crate::Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn serde_roundtrip() {
        let vek = Vek::random();
        let kek = random_key();
        let wrapped = vek.wrap(&kek).unwrap();
        let bytes = wrapped.to_bytes();
        let restored = WrappedVek::from_bytes(&bytes).unwrap();
        let unwrapped = restored.unwrap(&kek).unwrap();
        assert_eq!(unwrapped.as_key_bytes().as_bytes(), vek.as_key_bytes().as_bytes());
    }

    #[test]
    fn from_bytes_works() {
        let bytes = [0x42u8; 32];
        let vek = Vek::from_bytes(bytes);
        assert_eq!(vek.as_key_bytes().as_bytes(), &bytes);
    }
}
