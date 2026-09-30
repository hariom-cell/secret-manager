//! Vault file format — binary layout for persistent storage.
//!
//! ```text
//! ┌──────────────────────────────────────────────────┐
//! │ HEADER (fixed 256 bytes)                         │
//! │  magic:       [4]  b"VLT1"                       │
//! │  version:     [2]  u16 BE = 1                    │
//! │  flags:       [2]  u16 BE (reserved, zero)       │
//! │  kdf_params:  [12] m_cost(4) + t_cost(4) + p(4)  │
//! │  salt:        [32] Argon2id salt                  │
//! │  wrapped_vek: [72] nonce(24) + ct(48)             │
//! │  hmac:        [32] HMAC-SHA256                    │
//! │  reserved:    [100] zero padding                  │
//! └──────────────────────────────────────────────────┘
//! │ RECORDS (variable length)                         │
//! │  For each record:                                 │
//! │    record_id: [16]                                │
//! │    ct_len:    [4]  u32 BE                         │
//! │    nonce:     [24]                                │
//! │    ciphertext: [ct_len] (nonce || ct || tag)     │
//! └──────────────────────────────────────────────────┘
//! ```
//!
//! Total header is exactly 256 bytes. Records follow immediately.

use crate::{
    aead::Ciphertext,
    error::{Error, Result},
    integrity::Header as IntegrityHeader,
    kdf::KdfParams,
    types::KeyBytes,
    vek::WrappedVek,
    RecordId,
};
use std::io::{Read, Write};

/// Magic bytes identifying a vault file.
pub const VAULT_MAGIC: &[u8; 4] = b"VLT1";

/// Current file format version.
pub const VAULT_VERSION: u16 = 1;

/// Fixed size of the header in bytes.
pub const HEADER_SIZE: usize = 256;

/// Wrapped VEK size: 24 (nonce) + 48 (ciphertext) = 72 bytes.
pub const WRAPPED_VEK_SIZE: usize = 72;

/// HMAC-SHA256 tag size.
pub const HMAC_SIZE: usize = 32;

/// Offset of the HMAC tag in the header.
pub const HMAC_OFFSET: usize = 124;

/// Parse the vault file header from raw bytes.
///
/// Returns `(kdf_params, salt, wrapped_vek)` on success.
pub fn parse_header(bytes: &[u8]) -> Result<(KdfParams, [u8; 32], WrappedVek)> {
    if bytes.len() < HEADER_SIZE {
        return Err(Error::CiphertextTooShort { min: HEADER_SIZE, got: bytes.len() });
    }

    // Magic
    if &bytes[0..4] != VAULT_MAGIC {
        return Err(Error::Encoding("invalid magic bytes".into()));
    }

    // Version
    let version = u16::from_be_bytes([bytes[4], bytes[5]]);
    if version != VAULT_VERSION {
        return Err(Error::Encoding(format!("unsupported version: {version}")));
    }

    // KDF params: m_cost(4), t_cost(4), p_cost(4)
    let m_cost = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let t_cost = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let p_cost = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let kdf_params = KdfParams { m_cost, t_cost, p_cost };

    // Salt (32 bytes)
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&bytes[20..52]);

    // Wrapped VEK: 72 bytes at offset 52
    let wrapped_bytes = &bytes[52..52 + WRAPPED_VEK_SIZE];
    let wrapped_vek = WrappedVek::from_bytes(wrapped_bytes)?;

    Ok((kdf_params, salt, wrapped_vek))
}

/// Parse the vault file header including the HMAC integrity tag.
///
/// This function also returns the raw HMAC bytes so the caller can
/// verify them using [`IntegrityHeader::verify_mac`] with the KEK.
pub fn parse_header_with_mac(bytes: &[u8]) -> Result<(KdfParams, [u8; 32], WrappedVek, [u8; HMAC_SIZE])> {
    let hdr = IntegrityHeader::from_bytes(bytes)?;
    let mut mac = [0u8; HMAC_SIZE];
    mac.copy_from_slice(&bytes[HMAC_OFFSET..HMAC_OFFSET + HMAC_SIZE]);
    Ok((hdr.kdf_params, hdr.salt, hdr.wrapped_vek, mac))
}

/// Serialize a vault header to bytes.
///
/// # Arguments
/// - `kdf_params`: Argon2id parameters
/// - `salt`: 256-bit vault salt
/// - `wrapped_vek`: VEK encrypted under the KEK
pub fn serialize_header(kdf_params: KdfParams, salt: &[u8; 32], wrapped_vek: &WrappedVek) -> Vec<u8> {
    let mut header = vec![0u8; HEADER_SIZE];

    // Magic + version
    header[0..4].copy_from_slice(VAULT_MAGIC);
    header[4..6].copy_from_slice(&VAULT_VERSION.to_be_bytes());

    // KDF params
    header[8..12].copy_from_slice(&kdf_params.m_cost.to_be_bytes());
    header[12..16].copy_from_slice(&kdf_params.t_cost.to_be_bytes());
    header[16..20].copy_from_slice(&kdf_params.p_cost.to_be_bytes());

    // Salt
    header[20..52].copy_from_slice(salt);

    // Wrapped VEK: 72 bytes (24 nonce + 48 ciphertext)
    let wv_bytes = wrapped_vek.to_bytes();
    assert!(wv_bytes.len() == WRAPPED_VEK_SIZE, "wrapped VEK must be exactly 72 bytes, got {}", wv_bytes.len());
    header[52..52 + WRAPPED_VEK_SIZE].copy_from_slice(&wv_bytes);

    header
}

/// Serialize a vault header with HMAC-SHA256 integrity tag.
///
/// `hmac_key` is typically the KEK. The HMAC covers all header bytes
/// up to the HMAC slot (offset 124) so that any tampering is detected.
pub fn serialize_header_secure(
    kdf_params: KdfParams,
    salt: &[u8; 32],
    wrapped_vek: &WrappedVek,
    hmac_key: &KeyBytes,
) -> Vec<u8> {
    let integrity_hdr = IntegrityHeader {
        version: VAULT_VERSION,
        kdf_params,
        salt: *salt,
        wrapped_vek: wrapped_vek.clone(),
        hmac: [0u8; HMAC_SIZE],
    };
    let hmac = integrity_hdr.compute_mac(hmac_key.as_bytes());
    let full = IntegrityHeader {
        hmac,
        ..integrity_hdr
    };
    full.to_bytes().to_vec()
}

/// Serialize all records to bytes for writing to disk.
///
/// Each record is: `record_id(16) || ct_len(4) || nonce(24) || ciphertext_data`
pub fn serialize_records(
    records: &[(RecordId, Ciphertext)],
) -> Vec<u8> {
    let mut out = Vec::new();
    for (id, ct) in records {
        out.extend_from_slice(id);
        let ct_bytes = ct.to_bytes();
        out.extend_from_slice(&(ct_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&ct_bytes);
    }
    out
}

/// Deserialize records from bytes.
pub fn deserialize_records(bytes: &[u8]) -> Result<Vec<(RecordId, Ciphertext)>> {
    let mut records = Vec::new();
    let mut pos = 0;

    while pos + 20 <= bytes.len() {
        // record_id(16) + ct_len(4) = 20 bytes header per record
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes[pos..pos + 16]);
        pos += 16;

        let ct_len = u32::from_be_bytes([
            bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3],
        ]) as usize;
        pos += 4;

        if pos + ct_len > bytes.len() {
            return Err(Error::Encoding("truncated record data".into()));
        }

        let ct = Ciphertext::from_bytes(&bytes[pos..pos + ct_len])?;
        pos += ct_len;

        records.push((id, ct));
    }

    Ok(records)
}

/// Write a complete vault to a writer.
pub fn write_vault<W: Write>(
    mut writer: W,
    kdf_params: KdfParams,
    salt: &[u8; 32],
    wrapped_vek: &WrappedVek,
    records: &[(RecordId, Ciphertext)],
) -> Result<()> {
    let header = serialize_header(kdf_params, salt, wrapped_vek);
    writer.write_all(&header).map_err(|e| Error::Encoding(e.to_string()))?;
    let record_bytes = serialize_records(records);
    writer.write_all(&record_bytes).map_err(|e| Error::Encoding(e.to_string()))?;
    Ok(())
}

/// Read a complete vault from a reader.
///
/// Note: this reads the raw header and records without HMAC verification.
/// For HMAC-authenticated reads, use [`vault_core::Vault::unlock_existing`]
/// which re-derives the KEK, unwraps the VEK, and validates integrity.
pub fn read_vault<R: Read>(
    mut reader: R,
) -> Result<(KdfParams, [u8; 32], WrappedVek, Vec<(RecordId, Ciphertext)>)> {
    let mut header = [0u8; HEADER_SIZE];
    reader.read_exact(&mut header).map_err(|e| Error::Encoding(e.to_string()))?;

    let (kdf_params, salt, wrapped_vek) = parse_header(&header)?;

    let mut body = Vec::new();
    reader.read_to_end(&mut body).map_err(|e| Error::Encoding(e.to_string()))?;
    let records = deserialize_records(&body)?;

    Ok((kdf_params, salt, wrapped_vek, records))
}

/// Extract the HMAC tag from a vault header without parsing it fully.
pub fn extract_hmac(bytes: &[u8]) -> Result<[u8; HMAC_SIZE]> {
    if bytes.len() < HMAC_OFFSET + HMAC_SIZE {
        return Err(Error::CiphertextTooShort { min: HMAC_OFFSET + HMAC_SIZE, got: bytes.len() });
    }
    let mut mac = [0u8; HMAC_SIZE];
    mac.copy_from_slice(&bytes[HMAC_OFFSET..HMAC_OFFSET + HMAC_SIZE]);
    Ok(mac)
}

/// Verify the HMAC-SHA256 integrity tag on a vault header.
///
/// `hmac_key` should be the KEK derived from the master password.
/// `header_bytes` should be the full 256-byte header read from the file.
///
/// Returns `Ok(())` if the tag is valid, or
/// [`Error::IntegrityFailed`] if the file has been tampered with.
pub fn verify_header_integrity(header_bytes: &[u8], hmac_key: &KeyBytes) -> Result<()> {
    let integrity_hdr = IntegrityHeader::from_bytes(header_bytes)?;
    integrity_hdr.verify_mac(hmac_key.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::KeyBytes;
    use crate::{kdf::KdfParams, vek::Vek};

    fn test_wrapped_vek() -> WrappedVek {
        // Create a simple wrapped VEK using the VEK module directly.
        let vek_bytes = [0xABu8; 32];
        let kek_bytes = [0xCDu8; 32];
        let vek = Vek::from_bytes(vek_bytes);
        let kek = KeyBytes::new(kek_bytes);
        vek.wrap(&kek).unwrap()
    }

    #[test]
    fn header_roundtrip() {
        let params = KdfParams::default();
        let salt = [0x42u8; 32];
        let wrapped = test_wrapped_vek();

        let header = serialize_header(params, &salt, &wrapped);
        assert_eq!(header.len(), HEADER_SIZE);

        let (p2, s2, w2) = parse_header(&header).unwrap();
        assert_eq!(p2.m_cost, params.m_cost);
        assert_eq!(p2.t_cost, params.t_cost);
        assert_eq!(p2.p_cost, params.p_cost);
        assert_eq!(s2, salt);
        assert_eq!(w2.to_bytes(), wrapped.to_bytes());
    }

    #[test]
    fn header_magic_check() {
        let mut bad = vec![0u8; HEADER_SIZE];
        bad[0..4].copy_from_slice(b"BAD!");
        assert!(parse_header(&bad).is_err());
    }

    #[test]
    fn header_too_short() {
        assert!(parse_header(&[0u8; 100]).is_err());
    }

    #[test]
    fn records_roundtrip() {
        let records = vec![
            ([0x01u8; 16], Ciphertext { nonce: crate::aead::Nonce::from_bytes([0x11u8; 24]), data: vec![1, 2, 3] }),
            ([0x02u8; 16], Ciphertext { nonce: crate::aead::Nonce::from_bytes([0x22u8; 24]), data: vec![4, 5, 6] }),
        ];
        let bytes = serialize_records(&records);
        let recovered = deserialize_records(&bytes).unwrap();
        assert_eq!(recovered.len(), 2);
        assert_eq!(recovered[0].0, [0x01u8; 16]);
        assert_eq!(recovered[0].1.data, vec![1, 2, 3]);
        assert_eq!(recovered[1].0, [0x02u8; 16]);
        assert_eq!(recovered[1].1.data, vec![4, 5, 6]);
    }

    #[test]
    fn write_and_read_vault() {
        let params = KdfParams::default();
        let salt = [0x99u8; 32];
        let wrapped = test_wrapped_vek();
        let records = vec![
            ([0x01u8; 16], Ciphertext { nonce: crate::aead::Nonce::from_bytes([0x11u8; 24]), data: vec![10, 20, 30] }),
        ];

        let mut buf = Vec::new();
        write_vault(&mut buf, params, &salt, &wrapped, &records).unwrap();

        let (p2, s2, w2, recs) = read_vault(&buf[..]).unwrap();
        assert_eq!(p2.m_cost, params.m_cost);
        assert_eq!(s2, salt);
        assert_eq!(w2.to_bytes(), wrapped.to_bytes());
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].0, [0x01u8; 16]);
        assert_eq!(recs[0].1.data, vec![10, 20, 30]);
    }

    #[test]
    fn empty_records() {
        let params = KdfParams::default();
        let salt = [0x42u8; 32];
        let wrapped = test_wrapped_vek();

        let mut buf = Vec::new();
        write_vault(&mut buf, params, &salt, &wrapped, &[]).unwrap();

        let (_p, _s, _w, recs) = read_vault(&buf[..]).unwrap();
        assert!(recs.is_empty());
    }

    #[test]
    fn parse_header_validates_version() {
        let mut header = vec![0u8; HEADER_SIZE];
        header[0..4].copy_from_slice(VAULT_MAGIC);
        header[4..6].copy_from_slice(&2u16.to_be_bytes()); // unsupported version

        let result = parse_header(&header);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported version"));
    }
}
