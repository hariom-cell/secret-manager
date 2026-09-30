//! Vault backup and restore.
//!
//! Creates encrypted backup archives of vault state and restores from them.
//! The backup format is a structured binary:
//!
//! ```text
//! [ 4B  magic "VBAK" ]
//! [ 2B  version (0x0001) ]
//! [ 2B  reserved ]
//! [ 4B  Argon2id m_cost ]
//! [ 4B  Argon2id t_cost ]
//! [ 4B  Argon2id p_cost ]
//! [ 32B salt ]
//! [ 72B wrapped VEK (24B nonce + 48B ciphertext) ]
//! [ 4B  record count ]
//! [ for each record:
//!     [ 16B record ID ]
//!     [ 4B  ciphertext length ]
//!     [ ciphertext bytes ]
//! ]
//! ```
//!
//! ## Security
//!
//! - The backup carries only encrypted data: wrapped VEK + per-record ciphertexts.
//! - Records can only be decrypted after the master password is re-derived into KEK
//!   and used to unwrap VEK.
//! - A backup-passphrase layer (Argon2id-wrap of the KEK) can be added later by
//!   re-wrapping the VEK with a passphrase-derived KEK before backup.

use crate::error::{Error, Result};
use vault_core::{
    vault::{EncryptedRecord, Vault},
    vek::WrappedVek,
    KdfParams,
};

use std::io::{Read, Write};

/// Backup file magic bytes.
const BACKUP_MAGIC: &[u8; 4] = b"VBAK";
/// Backup format version.
const BACKUP_VERSION: u16 = 1;

/// Header size for the backup prelude (4 magic + 2 ver + 2 reserved + 12 KDF + 32 salt + 72 wrapped VEK).
const BACKUP_PRELUDE_SIZE: usize = 4 + 2 + 2 + 12 + 32 + 72;

/// Serialize an encrypted backup of vault state.
///
/// The vault must be unlocked.
pub fn backup_vault<W: Write>(vault: &Vault, output: &mut W) -> Result<()> {
    if !vault.is_unlocked() {
        return Err(Error::Other("vault is locked, cannot create backup".into()));
    }

    // Read header components from the in-memory vault representation.
    // We use the vault's stored KDF/salt/wrapped VEK.
    let kdf_params = vault.kdf_params();
    let salt = vault.salt();
    let wrapped_vek = vault
        .wrapped_vek()
        .map_err(|e| Error::Other(format!("wrapped VEK: {e}")))?;

    // Write header prelude
    output.write_all(BACKUP_MAGIC)?;
    output.write_all(&BACKUP_VERSION.to_le_bytes())?;
    output.write_all(&[0u8; 2])?; // reserved
    output.write_all(&kdf_params.m_cost.to_le_bytes())?;
    output.write_all(&kdf_params.t_cost.to_le_bytes())?;
    output.write_all(&kdf_params.p_cost.to_le_bytes())?;
    output.write_all(&salt)?;
    let wv_bytes = wrapped_vek.to_bytes();
    if wv_bytes.len() != 72 {
        return Err(Error::Other(format!(
            "unexpected wrapped VEK size: {}",
            wv_bytes.len()
        )));
    }
    output.write_all(&wv_bytes)?;

    // Write records
    let records: Vec<_> = vault.records().map(|(id, r)| (*id, r.clone())).collect();
    output.write_all(&(records.len() as u32).to_le_bytes())?;
    for (id, record) in &records {
        output.write_all(id)?;
        let ct_bytes = record.to_bytes();
        output.write_all(&(ct_bytes.len() as u32).to_le_bytes())?;
        output.write_all(&ct_bytes)?;
    }

    Ok(())
}

/// Restore vault data from a backup reader.
pub fn restore_vault<R: Read>(input: &mut R) -> Result<RestoredVault> {
    // Read and verify magic
    let mut magic = [0u8; 4];
    input.read_exact(&mut magic)?;
    if &magic != BACKUP_MAGIC {
        return Err(Error::Other("invalid backup format".into()));
    }

    // Read version
    let mut version = [0u8; 2];
    input.read_exact(&mut version)?;
    if u16::from_le_bytes(version) != BACKUP_VERSION {
        return Err(Error::Other("unsupported backup version".into()));
    }

    // Skip reserved
    let mut reserved = [0u8; 2];
    input.read_exact(&mut reserved)?;

    // Read KDF params
    let mut buf = [0u8; 4];
    input.read_exact(&mut buf)?;
    let m_cost = u32::from_le_bytes(buf);
    input.read_exact(&mut buf)?;
    let t_cost = u32::from_le_bytes(buf);
    input.read_exact(&mut buf)?;
    let p_cost = u32::from_le_bytes(buf);

    let kdf_params = KdfParams { m_cost, t_cost, p_cost };

    // Read salt
    let mut salt = [0u8; 32];
    input.read_exact(&mut salt)?;

    // Read wrapped VEK
    let mut wrapped_vek_bytes = [0u8; 72];
    input.read_exact(&mut wrapped_vek_bytes)?;
    let wrapped_vek = WrappedVek::from_bytes(&wrapped_vek_bytes)
        .map_err(|e| Error::Other(format!("wrapped VEK: {e}")))?;

    // Read records
    let mut record_count_buf = [0u8; 4];
    input.read_exact(&mut record_count_buf)?;
    let record_count = u32::from_le_bytes(record_count_buf) as usize;

    let mut records = Vec::with_capacity(record_count);
    for _ in 0..record_count {
        let mut id = [0u8; 16];
        input.read_exact(&mut id)?;

        let mut ct_len_buf = [0u8; 4];
        input.read_exact(&mut ct_len_buf)?;
        let ct_len = u32::from_le_bytes(ct_len_buf) as usize;

        let mut ciphertext = vec![0u8; ct_len];
        input.read_exact(&mut ciphertext)?;

        records.push((id, ciphertext));
    }

    Ok(RestoredVault {
        kdf_params,
        salt,
        wrapped_vek,
        records,
    })
}

/// Restored vault data that can be unlocked with the master password.
#[derive(Debug)]
pub struct RestoredVault {
    /// KDF parameters used to derive the KEK.
    pub kdf_params: KdfParams,
    /// Salt used for key derivation.
    pub salt: [u8; 32],
    /// Wrapped VEK.
    pub wrapped_vek: WrappedVek,
    /// Encrypted records (raw bytes per record).
    pub records: Vec<([u8; 16], Vec<u8>)>,
}

impl RestoredVault {
    /// Total size of the backup prelude (header part).
    pub fn prelude_size() -> usize {
        BACKUP_PRELUDE_SIZE
    }

    /// Unlock the restored vault with the master password and return it.
    pub fn unlock(self, password: &str) -> Result<Vault> {
        Vault::unlock_existing(password, self.kdf_params, self.salt, &self.wrapped_vek)
            .map_err(|e| Error::Other(format!("vault unlock: {e}")))
    }

    /// Build an [`EncryptedRecord`] from raw backup bytes.
    pub fn build_record(raw: &[u8]) -> Result<EncryptedRecord> {
        EncryptedRecord::from_bytes(raw).map_err(|e| Error::Other(format!("record: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault_core::vault::Vault;

    #[test]
    fn backup_and_restore_roundtrip() {
        let mut vault = Vault::create("test-password").unwrap();
        let id = [0x01u8; 16];
        vault.add_secret(id, b"secret-data-12345").unwrap();
        assert_eq!(vault.records().count(), 1);

        let mut buf = Vec::new();
        backup_vault(&vault, &mut buf).unwrap();

        assert!(buf.len() > BACKUP_PRELUDE_SIZE);
        assert_eq!(&buf[0..4], BACKUP_MAGIC);
        assert_eq!(u16::from_le_bytes([buf[4], buf[5]]), BACKUP_VERSION);

        let restored = restore_vault(&mut buf.as_slice()).unwrap();
        assert_eq!(restored.kdf_params, vault.kdf_params());
        assert_eq!(restored.salt, vault.salt());
        assert_eq!(restored.records.len(), 1);
    }

    #[test]
    fn backup_rejects_locked_vault() {
        let mut vault = Vault::create("test-password").unwrap();
        vault.lock();
        let mut buf = Vec::new();
        let result = backup_vault(&vault, &mut buf);
        assert!(result.is_err());
    }

    #[test]
    fn restore_rejects_invalid_magic() {
        let data = b"NOTV";
        let result = restore_vault(&mut data.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn restore_rejects_wrong_version() {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"VBAK");
        buf.extend_from_slice(&99u16.to_le_bytes()); // wrong version
        let result = restore_vault(&mut buf.as_slice());
        assert!(result.is_err());
    }

    #[test]
    fn multiple_records_roundtrip() {
        let mut vault = Vault::create("password").unwrap();
        vault.add_secret([0x01u8; 16], b"data-1").unwrap();
        vault.add_secret([0x02u8; 16], b"data-2").unwrap();
        vault.add_secret([0x03u8; 16], b"data-3").unwrap();

        let mut buf = Vec::new();
        backup_vault(&vault, &mut buf).unwrap();

        let restored = restore_vault(&mut buf.as_slice()).unwrap();
        assert_eq!(restored.records.len(), 3);
    }

    #[test]
    fn empty_vault_roundtrip() {
        let vault = Vault::create("password").unwrap();
        let mut buf = Vec::new();
        backup_vault(&vault, &mut buf).unwrap();

        let restored = restore_vault(&mut buf.as_slice()).unwrap();
        assert_eq!(restored.records.len(), 0);
    }
}
