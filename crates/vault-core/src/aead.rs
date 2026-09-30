//! Authenticated encryption using XChaCha20-Poly1305 (RFC 8439).
//!
//! This is the only AEAD used by the vault. All record encryption goes
//! through [`encrypt_record`] and [`decrypt_record`].
//!
//! ## Why XChaCha20-Poly1305
//!
//! - **192-bit nonce** (vs. 96-bit for AES-GCM). Random nonces from a
//!   CSPRNG are collision-safe without a counter, which removes an entire
//!   class of bugs (nonce reuse) that AES-GCM users have to defend against.
//! - **Consistent performance** across platforms (no AES-NI dependency).
//! - **Side-channel resistant** — the `chacha20poly1305` crate uses constant
//!   time Poly1305.
//!
//! ## Frame Format
//!
//! ```text
//! Ciphertext{
//!     nonce: [u8; 24],  // 192-bit random nonce
//!     data:  Vec<u8>,   // ciphertext || 16-byte Poly1305 tag
//! }
//! ```

use crate::{error::Result, types::KeyBytes};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use zeroize::Zeroize;

/// Size of an XChaCha20-Poly1305 nonce in bytes (192 bits).
pub const NONCE_SIZE: usize = 24;

/// Size of the Poly1305 authentication tag in bytes (128 bits).
pub const TAG_SIZE: usize = 16;

/// A single-use 192-bit nonce.
///
/// Generated randomly from the OS CSPRNG. With a 2^192 nonce space and
/// random (not counter-based) generation, collisions are not a concern
/// at any plausible scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Nonce([u8; NONCE_SIZE]);

impl Nonce {
    /// Generate a cryptographically random nonce.
    pub fn random() -> Self {
        let mut bytes = [0u8; NONCE_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Construct from raw bytes.
    pub fn from_bytes(bytes: [u8; NONCE_SIZE]) -> Self {
        Self(bytes)
    }

    /// Borrow the inner bytes.
    pub fn as_bytes(&self) -> &[u8; NONCE_SIZE] {
        &self.0
    }

    /// Consume and return the inner bytes.
    pub fn into_bytes(self) -> [u8; NONCE_SIZE] {
        self.0
    }
}

impl From<[u8; NONCE_SIZE]> for Nonce {
    fn from(bytes: [u8; NONCE_SIZE]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Nonce> for XNonce {
    fn from(n: Nonce) -> Self {
        // SAFETY: XNonce is `GenericArray<u8, U24>` whose backing bytes we
        // populate from a 24-byte array of the same length. The conversion
        // is the same as in the `chacha20poly1305` docs.
        *XNonce::from_slice(&n.0)
    }
}

/// Encrypted payload: random nonce prepended to ciphertext+tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ciphertext {
    /// Random nonce used for this encryption.
    pub nonce: Nonce,
    /// Ciphertext bytes with the 16-byte Poly1305 tag appended.
    pub data: Vec<u8>,
}

impl Drop for Ciphertext {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}

impl Ciphertext {
    /// Serialize to `nonce || ciphertext` for storage on disk.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NONCE_SIZE + self.data.len());
        out.extend_from_slice(self.nonce.as_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    /// Deserialize from `nonce || ciphertext` bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < NONCE_SIZE {
            return Err(crate::Error::CiphertextTooShort {
                min: NONCE_SIZE,
                got: bytes.len(),
            });
        }
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        nonce_bytes.copy_from_slice(&bytes[..NONCE_SIZE]);
        Ok(Self {
            nonce: Nonce::from_bytes(nonce_bytes),
            data: bytes[NONCE_SIZE..].to_vec(),
        })
    }
}

/// Encrypt plaintext with XChaCha20-Poly1305.
///
/// A fresh random nonce is generated for every call.
///
/// # Errors
/// Returns [`crate::Error::Crypto`] only if the underlying AEAD routine
/// rejects the key (which cannot happen for 32-byte keys with this cipher).
pub fn encrypt_record(key: &KeyBytes, plaintext: &[u8]) -> Result<Ciphertext> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    let nonce = Nonce::random();
    let ciphertext = cipher
        .encrypt(&XNonce::from(nonce), plaintext)
        .map_err(|e| crate::Error::Crypto(format!("encryption failed: {e}")))?;

    Ok(Ciphertext { nonce, data: ciphertext })
}

/// Decrypt a ciphertext with XChaCha20-Poly1305.
///
/// Returns [`crate::Error::AuthenticationFailed`] for any of:
/// - Wrong key
/// - Tampered ciphertext
/// - Truncated or extended ciphertext
///
/// The same error is returned in all three cases so an attacker cannot
/// distinguish them.
pub fn decrypt_record(key: &KeyBytes, ciphertext: &Ciphertext) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

    cipher
        .decrypt(&XNonce::from(ciphertext.nonce), ciphertext.data.as_ref())
        .map_err(|_| crate::Error::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic key for tests — never use in production.
    const TEST_KEY: [u8; 32] = [0xABu8; 32];

    fn test_key() -> KeyBytes {
        KeyBytes::new(TEST_KEY)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = test_key();
        let plaintext = b"secret password";
        let ct = encrypt_record(&key, plaintext).unwrap();
        let recovered = decrypt_record(&key, &ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn encrypt_empty_plaintext() {
        let key = test_key();
        let ct = encrypt_record(&key, b"").unwrap();
        let recovered = decrypt_record(&key, &ct).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn encrypt_non_empty_plaintext() {
        let key = test_key();
        let plaintext = b"The quick brown fox jumps over the lazy dog";
        let ct = encrypt_record(&key, plaintext).unwrap();
        let recovered = decrypt_record(&key, &ct).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn wrong_key_rejected() {
        let key1 = KeyBytes::new([0xAAu8; 32]);
        let key2 = KeyBytes::new([0xBBu8; 32]);
        let ct = encrypt_record(&key1, b"secret").unwrap();
        assert!(matches!(
            decrypt_record(&key2, &ct),
            Err(crate::Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn tampered_ciphertext_rejected() {
        let key = test_key();
        let ct = encrypt_record(&key, b"secret").unwrap();
        let mut tampered = ct.clone();
        tampered.data[0] ^= 0x01;
        assert!(matches!(
            decrypt_record(&key, &tampered),
            Err(crate::Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn nonce_length_correct() {
        let nonce = Nonce::random();
        assert_eq!(nonce.as_bytes().len(), 24);
    }

    #[test]
    fn ciphertext_serialization_roundtrip() {
        let key = test_key();
        let plaintext = b"test serialization";
        let ct = encrypt_record(&key, plaintext).unwrap();
        let bytes = ct.to_bytes();
        let recovered = Ciphertext::from_bytes(&bytes).unwrap();
        assert_eq!(recovered, ct);
        let plain = decrypt_record(&key, &recovered).unwrap();
        assert_eq!(plain, plaintext);
    }

    #[test]
    fn ciphertext_too_short() {
        let result = Ciphertext::from_bytes(&[0u8; 10]);
        assert!(matches!(
            result,
            Err(crate::Error::CiphertextTooShort { .. })
        ));
    }
}
