//! Vault file integrity verification using HMAC-SHA256.
//!
//! The vault header is authenticated with an HMAC keyed by a value derived
//! from the master password through the same Argon2id derivation that
//! produces the KEK. Because the HMAC key is unknown to an attacker without
//! the password, they cannot forge, swap, or rollback the header without being
//! noticed at the next unlock.
//!
//! ## Layout
//!
//! ```text
//! HEADER (256 bytes)
//!   bytes   0..4   magic
//!   bytes   4..6   version
//!   bytes   6..8   flags
//!   bytes   8..20  kdf params
//!   bytes  20..52  salt
//!   bytes  52..124 wrapped VEK
//!   bytes 124..156 HMAC-SHA256(key, header[0..124])
//!   bytes 156..256 reserved
//! ```
//!
//! The HMAC covers the header up to but not including the HMAC slot, so it
//! authenticates everything that the unlock path uses (magic, version,
//! KDF params, salt, wrapped VEK).

use crate::{
    error::{Error, Result},
    kdf::KdfParams,
    vek::WrappedVek,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// HMAC key slot offset in the header (bytes 124..156).
///
/// The 256-byte header layout is:
/// ```text
/// Offset  Size  Field
/// ──────  ──── ────────────────────────────
///   0      4    MAGIC ('V' 'L' 'T' 1)
///   4      2    FORMAT_VERSION
///   6      2    FLAGS (reserved)
///   8      12   KDF params (m_cost, t_cost, p_cost, each 4 bytes BE)
///  20      32   SALT
///  52      72   WRAPPED_VEK (nonce + ciphertext + tag)
/// 124      32   HMAC-SHA256 (keyed over bytes 0..124)
/// 156     100   RESERVED
/// ```
///
/// Total: 256 bytes = [`HEADER_SIZE`].
pub const HMAC_OFFSET: usize = 124;
/// Size of the HMAC-SHA256 tag in bytes (128 bits).
pub const HMAC_SIZE: usize = 32;
/// End offset (exclusive) of the HMAC slot: 124 + 32 = 156.
pub const HMAC_END: usize = HMAC_OFFSET + HMAC_SIZE;

/// Total fixed header size in bytes (256).
pub const HEADER_SIZE: usize = 256;

type HmacSha256 = Hmac<Sha256>;

/// A vault file header with optional HMAC integrity tag.
///
/// Plaintext fields are public so the struct can be created during
/// serialization; the [`Header::compute_mac`] and [`Header::verify_mac`]
/// methods handle HMAC computation and verification.
#[derive(Debug, Clone)]
pub struct Header {
    /// File format version.
    pub version: u16,
    /// KDF parameters.
    pub kdf_params: KdfParams,
    /// Vault salt.
    pub salt: [u8; 32],
    /// Wrapped VEK.
    pub wrapped_vek: WrappedVek,
    /// Computed HMAC-SHA256 tag (32 bytes).
    pub hmac: [u8; HMAC_SIZE],
}

impl PartialEq for Header {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.kdf_params == other.kdf_params
            && self.salt == other.salt
            && self.wrapped_vek.to_bytes() == other.wrapped_vek.to_bytes()
            && self.hmac == other.hmac
    }
}

impl Eq for Header {}

impl Header {
    /// Serialize the header to bytes (including HMAC slot).
    pub fn to_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut out = [0u8; HEADER_SIZE];
        // Magic "VLT1"
        out[0..4].copy_from_slice(b"VLT1");
        // Version (BE)
        out[4..6].copy_from_slice(&self.version.to_be_bytes());
        // Flags (reserved, zero)
        out[6..8].copy_from_slice(&[0u8; 2]);
        // KDF params (m_cost BE, t_cost BE, p_cost BE)
        out[8..12].copy_from_slice(&self.kdf_params.m_cost.to_be_bytes());
        out[12..16].copy_from_slice(&self.kdf_params.t_cost.to_be_bytes());
        out[16..20].copy_from_slice(&self.kdf_params.p_cost.to_be_bytes());
        // Salt
        out[20..52].copy_from_slice(&self.salt);
        // Wrapped VEK (72 bytes)
        let wv = self.wrapped_vek.to_bytes();
        debug_assert_eq!(wv.len(), 72);
        out[52..124].copy_from_slice(&wv);
        // HMAC
        out[HMAC_OFFSET..HMAC_END].copy_from_slice(&self.hmac);
        out
    }

    /// Parse the header from raw bytes. Does NOT verify the HMAC — call
    /// [`Header::verify_mac`] with the derived HMAC key to verify integrity.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            return Err(Error::CiphertextTooShort { min: HEADER_SIZE, got: bytes.len() });
        }
        if &bytes[0..4] != b"VLT1" {
            return Err(Error::Encoding("invalid magic bytes".into()));
        }
        let version = u16::from_be_bytes([bytes[4], bytes[5]]);
        let m_cost = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let t_cost = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let p_cost = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes[20..52]);
        let wrapped_vek = WrappedVek::from_bytes(&bytes[52..124])?;
        let mut hmac = [0u8; HMAC_SIZE];
        hmac.copy_from_slice(&bytes[HMAC_OFFSET..HMAC_END]);
        Ok(Self {
            version,
            kdf_params: KdfParams { m_cost, t_cost, p_cost },
            salt,
            wrapped_vek,
            hmac,
        })
    }

    /// Compute the HMAC-SHA256 over the header bytes (everything up to
    /// but NOT including the HMAC slot).
    pub fn compute_mac(&self, key: &[u8; 32]) -> [u8; HMAC_SIZE] {
        let bytes = self.to_bytes();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
            .expect("HMAC accepts any key length");
        mac.update(&bytes[..HMAC_OFFSET]);
        let result = mac.finalize();
        let bytes = result.into_bytes();
        let mut out = [0u8; HMAC_SIZE];
        out.copy_from_slice(&bytes);
        out
    }

    /// Verify the HMAC tag in the header using the supplied key.
    ///
    /// Returns `Ok(())` if the tag is valid, or
    /// [`Error::IntegrityFailed`] otherwise. The verify uses constant-time
    /// comparison.
    pub fn verify_mac(&self, key: &[u8; 32]) -> Result<()> {
        let computed = self.compute_mac(key);
        if !crate::crypto::constant_time_eq_array(&computed, &self.hmac) {
            return Err(Error::IntegrityFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KeyBytes;
    use crate::vek::Vek;

    fn test_header() -> Header {
        let vek_bytes = [0xABu8; 32];
        let kek_bytes = [0xCDu8; 32];
        let vek = Vek::from_bytes(vek_bytes);
        let kek = KeyBytes::new(kek_bytes);
        let wrapped = vek.wrap(&kek).unwrap();
        Header {
            version: 1,
            kdf_params: KdfParams::default(),
            salt: [0x42u8; 32],
            wrapped_vek: wrapped,
            hmac: [0u8; HMAC_SIZE],
        }
    }

    #[test]
    fn roundtrip_with_mac() {
        let key = [0x77u8; 32];
        let mut h = test_header();
        h.hmac = h.compute_mac(&key);
        let bytes = h.to_bytes();
        let parsed = Header::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.salt, [0x42u8; 32]);
        assert_eq!(parsed.kdf_params, h.kdf_params);
        assert!(parsed.verify_mac(&key).is_ok());
    }

    #[test]
    fn wrong_key_fails_verification() {
        let key = [0x77u8; 32];
        let mut h = test_header();
        h.hmac = h.compute_mac(&key);
        let bytes = h.to_bytes();
        let parsed = Header::from_bytes(&bytes).unwrap();
        let wrong = [0x88u8; 32];
        assert!(parsed.verify_mac(&wrong).is_err());
    }

    #[test]
    fn tampered_salt_fails_verification() {
        let key = [0x77u8; 32];
        let mut h = test_header();
        h.hmac = h.compute_mac(&key);
        let mut bytes = h.to_bytes();
        bytes[30] ^= 0x01;
        let parsed = Header::from_bytes(&bytes).unwrap();
        assert!(parsed.verify_mac(&key).is_err());
    }

    #[test]
    fn tampered_wrapped_vek_fails_verification() {
        let key = [0x77u8; 32];
        let mut h = test_header();
        h.hmac = h.compute_mac(&key);
        let mut bytes = h.to_bytes();
        bytes[80] ^= 0x01;
        let parsed = Header::from_bytes(&bytes).unwrap();
        assert!(parsed.verify_mac(&key).is_err());
    }

    #[test]
    fn bad_magic_rejected() {
        let mut bytes = [0u8; HEADER_SIZE];
        bytes[0..4].copy_from_slice(b"BAAD");
        let r = Header::from_bytes(&bytes);
        assert!(r.is_err());
    }

    #[test]
    fn too_short_rejected() {
        let r = Header::from_bytes(&[0u8; 100]);
        assert!(r.is_err());
    }
}