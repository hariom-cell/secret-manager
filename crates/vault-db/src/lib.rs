//! File-backed encrypted vault storage using vault-core's binary format.
//!
//! [`VaultFile`] wraps a [`vault_core::Vault`] with persistent I/O.

pub mod error;

// Re-export error types at the crate root for consumers and tests.
pub use crate::error::{DbError, DbResult};

use std::path::Path;

use vault_core::{
    self,
    format::{read_vault, verify_header_integrity},
    kdf::derive_kek,
    EncryptedRecord, RecordId, Vault,
};

/// A file-backed encrypted vault.
pub struct VaultFile {
    vault: Option<Vault>,
    path: std::path::PathBuf,
}

impl VaultFile {
    /// Open an existing vault file (returns locked).
    pub fn open(path: impl Into<std::path::PathBuf>) -> DbResult<Self> {
        let path = path.into();
        let data = std::fs::read(&path).map_err(DbError::Io)?;
        if data.len() < vault_core::HEADER_SIZE {
            return Err(DbError::InvalidFormat(format!(
                "file too short: {} bytes (expected at least {})",
                data.len(),
                vault_core::HEADER_SIZE,
            )));
        }
        if &data[..4] != vault_core::VAULT_MAGIC {
            return Err(DbError::InvalidFormat(
                "invalid vault magic bytes".into(),
            ));
        }
        Ok(Self { vault: None, path })
    }

    /// Create a new encrypted vault file.
    pub fn create(path: impl Into<std::path::PathBuf>, password: &str) -> DbResult<Self> {
        let path = path.into();
        let vault = Vault::create(password)?;
        let header = vault.serialize_header();
        std::fs::write(&path, header).map_err(DbError::Io)?;
        Ok(Self {
            vault: Some(vault),
            path,
        })
    }

    /// Unlock the vault with the master password.
    pub fn unlock(&mut self, password: &str) -> DbResult<&Vault> {
        if self.vault.is_some() {
            return Err(DbError::VaultLocked);
        }
        let data = std::fs::read(&self.path).map_err(DbError::Io)?;
        let (kdf_params, salt, wrapped_vek, records) =
            read_vault(&*data).map_err(|e| DbError::InvalidFormat(e.to_string()))?;

        // Verify HMAC integrity before unlocking — detects tampering
        let kek = derive_kek(password, &salt, kdf_params)?;
        let header_bytes = &data[..vault_core::HEADER_SIZE];
        verify_header_integrity(header_bytes, &kek)
            .map_err(|e| DbError::InvalidFormat(e.to_string()))?;

        let mut vault =
            Vault::unlock_existing(password, kdf_params, salt, &wrapped_vek)?;

        for (id, ciphertext) in records {
            vault.records_mut().insert(id, EncryptedRecord { ciphertext, wrapped_dek: None });
        }

        self.vault = Some(vault);
        Ok(self.vault.as_ref().unwrap())
    }

    /// Lock the vault, zeroizing all key material.
    pub fn lock(&mut self) -> DbResult<()> {
        if let Some(mut vault) = self.vault.take() {
            vault.lock();
        }
        Ok(())
    }

    /// Returns `true` if the vault is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.vault.is_some()
    }

    /// Persist the vault header + all records to disk.
    pub fn save(&self) -> DbResult<()> {
        let vault = self.vault.as_ref().ok_or(DbError::VaultLocked)?;
        let records: Vec<_> = vault
            .records()
            .map(|(id, enc)| (*id, enc.ciphertext.clone()))
            .collect();
        let header = vault.serialize_header();
        let mut out = Vec::with_capacity(vault_core::HEADER_SIZE);
        out.extend_from_slice(&header);
        let record_bytes = vault_core::format::serialize_records(&records);
        out.extend_from_slice(&record_bytes);
        std::fs::write(&self.path, out).map_err(DbError::Io)?;
        Ok(())
    }

    /// Add or update a secret record and persist to disk.
    pub fn put_secret(&mut self, id: RecordId, plaintext: &[u8]) -> DbResult<()> {
        let vault = self.vault_mut()?;
        vault.add_secret(id, plaintext)?;
        self.save()
    }

    /// Retrieve and decrypt a secret record.
    pub fn get_secret(&self, id: RecordId) -> DbResult<Vec<u8>> {
        let vault = self.vault()?;
        vault
            .get_secret(&id)
            .map_err(DbError::Vault)
    }

    /// Remove a secret record and persist to disk.
    pub fn remove_secret(&mut self, id: RecordId) -> DbResult<()> {
        let vault = self.vault_mut()?;
        vault.remove_secret(&id)?;
        self.save()
    }

    /// List all record IDs in the vault.
    pub fn list_records(&self) -> DbResult<Vec<RecordId>> {
        let vault = self.vault()?;
        Ok(vault.records().map(|(id, _)| *id).collect())
    }

    /// Number of records in the vault.
    pub fn record_count(&self) -> usize {
        self.vault
            .as_ref()
            .map(|v| v.record_count())
            .unwrap_or(0)
    }

    /// Returns the vault file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns a reference to the unlocked vault.
    pub fn vault(&self) -> DbResult<&Vault> {
        self.vault
            .as_ref()
            .ok_or(DbError::VaultLocked)
    }

    /// Returns a mutable reference to the unlocked vault.
    pub fn vault_mut(&mut self) -> DbResult<&mut Vault> {
        self.vault
            .as_mut()
            .ok_or(DbError::VaultLocked)
    }

    /// Consume the store and return the inner vault.
    pub fn into_vault(self) -> DbResult<Vault> {
        self.vault.ok_or(DbError::VaultLocked)
    }
}
