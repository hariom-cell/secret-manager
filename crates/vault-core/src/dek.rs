//! Per-record Data Encryption Keys (DEK).
//!
//! Every record gets its own unique encryption key.  Two mechanisms:
//!
//! **HKDF derivation** (default, lightweight):
//! ```text
//! VEK ──HKDF-SHA256(info = "vault-record-v1" || record_id)──► DEK
//! ```
//! - No extra storage per record.
//! - DEK is re-derived on every encrypt/decrypt.
//! - Changing the VEK automatically changes all DEKs.
//!
//! **Random + wrapping** (for sharing / granular rotation):
//! ```text
//! DEK_random ──XChaCha20-Poly1305(VEK)──► wrapped_dek
//! ```
//! - Stored encrypted under VEK alongside each record.
//! - Enables per-record key rotation and individual DEK zeroization.
//! - Used by the sharing protocol.

use crate::aead::{encrypt_record, decrypt_record, Ciphertext};
use crate::types::KeyBytes;
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A 256-bit per-record encryption key.
///
/// Never stored directly — derived fresh from the VEK on every encrypt/decrypt
/// when using HKDF mode, or unwrapped from a `WrappedDek` when using the
/// random-DEK mode.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecordKey(KeyBytes);

impl RecordKey {
    /// Create from raw bytes.
    pub fn from_key_bytes(key: KeyBytes) -> Self {
        Self(key)
    }

    /// Borrow the underlying key bytes.
    pub fn as_key_bytes(&self) -> &KeyBytes {
        &self.0
    }

    /// Consume and return the inner key bytes.
    pub fn into_key_bytes(self) -> KeyBytes {
        self.0.clone()
    }
}

/// A DEK encrypted under the VEK for storage.
///
/// Format: 24-byte nonce + ciphertext (32-byte DEK + 16-byte Poly1305 tag).
#[derive(Debug, Clone)]
pub struct WrappedDek {
    ciphertext: Ciphertext,
}

impl Drop for WrappedDek {
    fn drop(&mut self) {
        // The inner Ciphertext already zeroes its data on drop.
        // This Drop is here so that `WrappedDek: Drop`, which lets us
        // chain further zeroization in the future without changing
        // call sites.
    }
}

impl WrappedDek {
    /// Serialize to raw bytes (nonce || ciphertext || tag).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.ciphertext.to_bytes()
    }

    /// Deserialize from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        Ok(Self { ciphertext: Ciphertext::from_bytes(bytes)? })
    }

    /// Unwrap with the VEK to recover the DEK.
    pub fn unwrap(&self, vek: &KeyBytes) -> crate::Result<RecordKey> {
        let mut plaintext = decrypt_record(vek, &self.ciphertext)?;
        if plaintext.len() != 32 {
            return Err(crate::Error::InvalidKeyLength {
                expected: 32,
                got: plaintext.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&plaintext);
        plaintext.zeroize();
        Ok(RecordKey::from_key_bytes(KeyBytes::new(bytes)))
    }
}

/// Derive a DEK from the VEK using HKDF-SHA256 for a specific record.
///
/// # HKDF Parameters (RFC 5869)
/// - **IKM**: VEK bytes (32 bytes, high-entropy)
/// - **Salt**: `None` — the VEK itself is sufficient entropy
/// - **Info**: `b"vault-record-v1" || record_id`
/// - **Output**: 32 bytes
///
/// The version-prefixed `info` string means a future protocol change
/// (v2) will produce different DEKs without breaking old records.
pub fn derive_dek(vek: &KeyBytes, record_id: &[u8]) -> crate::Result<RecordKey> {
    let hk = Hkdf::<Sha256>::new(None, vek.as_bytes());
    let mut info = Vec::with_capacity(14 + record_id.len());
    info.extend_from_slice(b"vault-record-v1");
    info.extend_from_slice(record_id);

    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .map_err(|e| crate::Error::Crypto(format!("HKDF expansion failed: {e}")))?;

    Ok(RecordKey::from_key_bytes(KeyBytes::new(okm)))
}

/// Generate a random DEK for envelope encryption.
///
/// The returned key is cryptographically random. It should be wrapped with
/// [`wrap_dek`] before storage, and unwrapped when needed for decryption.
pub fn random_dek() -> RecordKey {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    RecordKey::from_key_bytes(KeyBytes::new(bytes))
}

/// Wrap (encrypt) a DEK under the VEK for storage.
///
/// Uses XChaCha20-Poly1305 with a fresh random nonce.
pub fn wrap_dek(vek: &KeyBytes, dek: &RecordKey) -> crate::Result<WrappedDek> {
    let ct = encrypt_record(vek, dek.as_key_bytes().as_bytes())?;
    Ok(WrappedDek { ciphertext: ct })
}

/// Unwrap (decrypt) a DEK that was encrypted under the VEK.
pub fn unwrap_dek(vek: &KeyBytes, wrapped: &WrappedDek) -> crate::Result<RecordKey> {
    wrapped.unwrap(vek)
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vek() -> KeyBytes {
        KeyBytes::new([0xAAu8; 32])
    }

    // HKDF derivation tests

    #[test]
    fn derive_dek_returns_32_bytes() {
        let dek = derive_dek(&test_vek(), b"record-1").unwrap();
        assert_eq!(dek.as_key_bytes().as_bytes().len(), 32);
    }

    #[test]
    fn different_record_ids_produce_different_deks() {
        let dek1 = derive_dek(&test_vek(), b"record-1").unwrap();
        let dek2 = derive_dek(&test_vek(), b"record-2").unwrap();
        assert_ne!(dek1.as_key_bytes().as_bytes(), dek2.as_key_bytes().as_bytes());
    }

    #[test]
    fn same_input_produces_same_dek() {
        let a = derive_dek(&test_vek(), b"record-1").unwrap();
        let b = derive_dek(&test_vek(), b"record-1").unwrap();
        assert_eq!(a.as_key_bytes().as_bytes(), b.as_key_bytes().as_bytes());
    }

    #[test]
    fn empty_record_id_produces_valid_dek() {
        let dek = derive_dek(&test_vek(), b"").unwrap();
        assert_eq!(dek.as_key_bytes().as_bytes().len(), 32);
    }

    #[test]
    fn different_vek_different_dek() {
        let vek1 = KeyBytes::new([0xAAu8; 32]);
        let vek2 = KeyBytes::new([0xBBu8; 32]);
        let dek1 = derive_dek(&vek1, b"record-1").unwrap();
        let dek2 = derive_dek(&vek2, b"record-1").unwrap();
        assert_ne!(dek1.as_key_bytes().as_bytes(), dek2.as_key_bytes().as_bytes());
    }

    #[test]
    fn dek_roundtrip_with_aead() {
        let vek = test_vek();
        let dek = derive_dek(&vek, b"my-record").unwrap();
        let key = dek.as_key_bytes();
        let ct = encrypt_record(key, b"my secret data").unwrap();
        let recovered = decrypt_record(key, &ct).unwrap();
        assert_eq!(recovered, b"my secret data");
    }

    #[test]
    fn different_dek_produces_different_ciphertext() {
        let vek = test_vek();
        let dek1 = derive_dek(&vek, b"record-1").unwrap();
        let dek2 = derive_dek(&vek, b"record-2").unwrap();
        let ct1 = encrypt_record(dek1.as_key_bytes(), b"same plaintext").unwrap();
        let ct2 = encrypt_record(dek2.as_key_bytes(), b"same plaintext").unwrap();
        assert_ne!(ct1.data, ct2.data);
    }

    // Random DEK + wrap/unwrap tests

    #[test]
    fn random_dek_is_unique() {
        let a = random_dek();
        let b = random_dek();
        assert_ne!(a.as_key_bytes().as_bytes(), b.as_key_bytes().as_bytes());
    }

    #[test]
    fn random_dek_roundtrip_wrap_unwrap() {
        let vek = test_vek();
        let dek = random_dek();
        let wrapped = wrap_dek(&vek, &dek).unwrap();
        let recovered = unwrap_dek(&vek, &wrapped).unwrap();
        assert_eq!(recovered.as_key_bytes().as_bytes(), dek.as_key_bytes().as_bytes());
    }

    #[test]
    fn wrong_vek_fails_unwrap() {
        let vek1 = KeyBytes::new([0xAAu8; 32]);
        let vek2 = KeyBytes::new([0xBBu8; 32]);
        let dek = random_dek();
        let wrapped = wrap_dek(&vek1, &dek).unwrap();
        assert!(unwrap_dek(&vek2, &wrapped).is_err());
    }

    #[test]
    fn wrapped_dek_serializes_correctly() {
        let vek = test_vek();
        let dek = random_dek();
        let wrapped = wrap_dek(&vek, &dek).unwrap();

        let bytes = wrapped.to_bytes();
        assert_eq!(bytes.len(), 72); // 24 nonce + 48 ct+tag

        let restored = WrappedDek::from_bytes(&bytes).unwrap();
        let recovered = restored.unwrap(&vek).unwrap();
        assert_eq!(recovered.as_key_bytes().as_bytes(), dek.as_key_bytes().as_bytes());
    }

    #[test]
    fn same_dek_different_wraps_produce_different_ciphertexts() {
        let vek = test_vek();
        let dek = random_dek();
        let w1 = wrap_dek(&vek, &dek).unwrap();
        let w2 = wrap_dek(&vek, &dek).unwrap();
        assert_ne!(w1.to_bytes(), w2.to_bytes());
    }

    #[test]
    fn random_dek_can_encrypt_decrypt_data() {
        use crate::aead::{encrypt_record, decrypt_record};
        let vek = test_vek();
        let dek = random_dek();
        let key = dek.as_key_bytes();

        let ct = encrypt_record(key, b"hello world").unwrap();
        let pt = decrypt_record(key, &ct).unwrap();
        assert_eq!(pt, b"hello world");
    }
}
