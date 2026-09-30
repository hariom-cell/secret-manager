//! Vault — the top-level orchestrator that wires the full key hierarchy together.
//!
//! ```text
//! User types password
//!       │
//!       ▼
//!  ┌─────────┐    Argon2id     ┌─────┐
//!  │ password │───────────────►│ KEK │
//!  └─────────┘                 └──┬──┘
//!                                 │ unwraps wrapped VEK
//!                                 ▼
//!                              ┌─────┐
//!                              │ VEK │
//!                              └──┬──┘
//!                                 │ HKDF(record_id)
//!                                 ▼
//!                              ┌─────┐    XChaCha20-Poly1305
//!                              │ DEK │──────────────► ciphertext
//!                              └─────┘
//! ```
//!
//! ## Lifecycle
//!
//! 1. **Create**: `Vault::create(password)` — random salt + random VEK, KEK derived
//! 2. **Unlock**: `vault.unlock(password, wrapped_vek)` — re-derive KEK, unwrap VEK
//! 3. **Operate**: `add_secret` / `get_secret` / `remove_secret`
//! 4. **Lock**: `vault.lock()` — zeros KEK + VEK from memory
//! 5. **Save**: returns wrapped VEK + encrypted records for persistence

use crate::{
    aead::{decrypt_record, encrypt_record, Ciphertext},
    dek::{derive_dek, WrappedDek},
    error::{Error, Result},
    kdf::{derive_kek, KdfParams},
    types::KeyBytes,
    vek::{Vek, WrappedVek},
};
use getrandom::getrandom;
use std::collections::HashMap;
use zeroize::Zeroize;

/// Unique identifier for a vault record (16 bytes).
pub type RecordId = [u8; 16];

/// An encrypted record stored in the vault.
///
/// Two modes:
/// - **HKDF mode** (default): DEK is derived from VEK + record_id. Only
///   `ciphertext` is stored.
/// - **Wrap mode** (for sharing): A random DEK was generated, encrypted under
///   the VEK, and stored as `wrapped_dek`. Both fields are present.
#[derive(Debug, Clone)]
pub struct EncryptedRecord {
    /// The ciphertext (nonce || encrypted || tag) produced by encrypt_record.
    pub ciphertext: Ciphertext,
    /// Optional wrapped DEK — present when the record was encrypted with a
    /// random DEK (needed for key sharing / individual key rotation).
    pub wrapped_dek: Option<WrappedDek>,
}

impl Drop for EncryptedRecord {
    fn drop(&mut self) {
        self.ciphertext.data.zeroize();
    }
}

impl EncryptedRecord {
    /// Serialize to bytes for storage (`nonce || ciphertext || tag`).
    pub fn to_bytes(&self) -> Vec<u8> {
        self.ciphertext.to_bytes()
    }

    /// Deserialize from stored bytes.
    pub fn from_bytes(bytes: &[u8]) -> crate::Result<Self> {
        Ok(Self {
            ciphertext: crate::Ciphertext::from_bytes(bytes)?,
            wrapped_dek: None,
        })
    }
}

/// The in-memory vault — holds KEK and VEK while unlocked.
pub struct Vault {
    /// Argon2id parameters — stored with the vault file header.
    kdf_params: KdfParams,
    /// 256-bit vault salt — stored with the vault file.
    salt: [u8; 32],
    /// Key Encryption Key (memory-only, never persisted).
    kek: Option<KeyBytes>,
    /// Vault Encryption Key (memory-only, wrapped for persistence).
    vek: Option<Vek>,
    /// Encrypted records keyed by record ID.
    records: HashMap<RecordId, EncryptedRecord>,
}

impl Vault {
    /// Create a new vault from a master password.
    pub fn create(password: &str) -> Result<Self> {
        let salt = Self::random_salt();
        let kdf_params = KdfParams::default();
        let kek = derive_kek(password, &salt, kdf_params)?;
        let vek = Vek::random();

        Ok(Self {
            kdf_params,
            salt,
            kek: Some(kek),
            vek: Some(vek),
            records: HashMap::new(),
        })
    }

    /// Unlock an existing vault from persisted parameters + wrapped VEK.
    pub fn unlock_existing(
        password: &str,
        kdf_params: KdfParams,
        salt: [u8; 32],
        wrapped_vek: &WrappedVek,
    ) -> Result<Self> {
        kdf_params.validate()?;
        let kek = derive_kek(password, &salt, kdf_params)?;
        let vek = wrapped_vek.unwrap(&kek)?;
        let vault = Self {
            kdf_params,
            salt,
            kek: Some(kek),
            vek: Some(vek),
            records: HashMap::new(),
        };
        Ok(vault)
    }

    /// Unlock an existing vault with a password + wrapped VEK (using stored salt).
    pub fn unlock(&mut self, password: &str, wrapped_vek: &WrappedVek) -> Result<()> {
        self.kdf_params.validate()?;
        let kek = derive_kek(password, &self.salt, self.kdf_params)?;
        let vek = wrapped_vek.unwrap(&kek)?;

        self.kek = Some(kek);
        self.vek = Some(vek);
        Ok(())
    }

    /// Add a secret record to the vault.
    pub fn add_secret(&mut self, record_id: RecordId, plaintext: &[u8]) -> Result<()> {
        let dek = self.derive_dek(&record_id)?;
        let ciphertext = encrypt_record(dek.as_key_bytes(), plaintext)?;
        self.records.insert(record_id, EncryptedRecord {
            ciphertext,
            wrapped_dek: None,
        });
        Ok(())
    }

    /// Retrieve and decrypt a secret record.
    pub fn get_secret(&self, record_id: &RecordId) -> Result<Vec<u8>> {
        let dek = self.derive_dek(record_id)?;
        let record = self.records
            .get(record_id)
            .ok_or(Error::Internal("record not found".into()))?;
        decrypt_record(dek.as_key_bytes(), &record.ciphertext)
    }

    /// Remove a record from the vault.
    pub fn remove_secret(&mut self, record_id: &RecordId) -> Result<EncryptedRecord> {
        self.records
            .remove(record_id)
            .ok_or(Error::Internal("record not found".into()))
    }

    /// Lock the vault — zero KEK and VEK from memory.
    pub fn lock(&mut self) {
        if let Some(mut kek) = self.kek.take() {
            kek.zero();
        }
        if let Some(vek) = self.vek.take() {
            // Vek implements ZeroizeOnDrop; consuming it here scrubs the bytes.
            drop(vek);
        }
    }

    /// Whether the vault is currently unlocked.
    pub fn is_unlocked(&self) -> bool {
        self.kek.is_some() && self.vek.is_some()
    }

    /// Number of records in the vault.
    pub fn record_count(&self) -> usize {
        self.records.len()
    }

    /// Wrap the VEK for persistence (requires vault to be unlocked).
    pub fn wrapped_vek(&self) -> Result<WrappedVek> {
        let kek = self.require_unlocked_kek()?;
        self.vek
            .as_ref()
            .ok_or(Error::Internal("missing VEK".into()))
            .and_then(|vek| vek.wrap(kek))
    }

    /// Serialize the 256-byte vault header (including HMAC for integrity).
    pub fn serialize_header(&self) -> Vec<u8> {
        let wrapped = self
            .wrapped_vek()
            .expect("vault must be unlocked to serialize header");
        let kek = self.require_unlocked_kek().unwrap();
        crate::format::serialize_header_secure(self.kdf_params, &self.salt, &wrapped, kek)
    }

    /// Return a copy of the vault salt (for serialization).
    pub fn salt(&self) -> [u8; 32] {
        self.salt
    }

    /// Return the KDF parameters (for serialization).
    pub fn kdf_params(&self) -> KdfParams {
        self.kdf_params
    }

    /// Borrow the raw VEK bytes (only when unlocked).
    pub fn vek_bytes(&self) -> &KeyBytes {
        self.vek.as_ref().unwrap().as_key_bytes()
    }

    /// Iterate over (record_id, ciphertext) pairs for serialization.
    pub fn records(&self) -> impl Iterator<Item = (&RecordId, &EncryptedRecord)> {
        self.records.iter()
    }

    /// Insert an encrypted record directly (for lazy-loading from storage).
    pub fn records_mut(&mut self) -> &mut HashMap<RecordId, EncryptedRecord> {
        &mut self.records
    }

    // --- private helpers ---

    fn random_salt() -> [u8; 32] {
        let mut salt = [0u8; 32];
        getrandom(&mut salt).expect("OS CSPRNG failure");
        salt
    }

    fn require_unlocked_kek(&self) -> Result<&KeyBytes> {
        self.kek.as_ref().ok_or(Error::Internal("vault is locked".into()))
    }

    fn derive_dek(&self, record_id: &RecordId) -> Result<crate::dek::RecordKey> {
        let _kek = self.require_unlocked_kek()?;
        let vek = self.vek.as_ref().ok_or(Error::Internal("missing VEK".into()))?;
        derive_dek(vek.as_key_bytes(), record_id)
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.lock();
        self.salt.zeroize();
        self.kdf_params.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unlocked_vault() -> Vault {
        Vault::create("correct horse battery staple").unwrap()
    }

    #[test]
    fn create_produces_salt_and_keys() {
        let vault = unlocked_vault();
        assert!(vault.is_unlocked());
        assert_eq!(vault.salt().len(), 32);
        assert_eq!(vault.record_count(), 0);
    }

    #[test]
    fn add_and_get_secret_roundtrip() {
        let mut vault = unlocked_vault();
        let id = [0x01u8; 16];
        vault.add_secret(id, b"my password").unwrap();
        assert_eq!(vault.record_count(), 1);
        let recovered = vault.get_secret(&id).unwrap();
        assert_eq!(recovered, b"my password");
    }

    #[test]
    fn add_multiple_records() {
        let mut vault = unlocked_vault();
        vault.add_secret([0x01u8; 16], b"password 1").unwrap();
        vault.add_secret([0x02u8; 16], b"password 2").unwrap();
        vault.add_secret([0x03u8; 16], b"password 3").unwrap();
        assert_eq!(vault.record_count(), 3);

        assert_eq!(vault.get_secret(&[0x01u8; 16]).unwrap(), b"password 1");
        assert_eq!(vault.get_secret(&[0x02u8; 16]).unwrap(), b"password 2");
        assert_eq!(vault.get_secret(&[0x03u8; 16]).unwrap(), b"password 3");
    }

    #[test]
    fn record_ids_produce_different_deks() {
        // Same vault, different IDs → different ciphertexts for same plaintext.
        let mut vault = unlocked_vault();
        vault.add_secret([0x01u8; 16], b"same plaintext").unwrap();
        vault.add_secret([0x02u8; 16], b"same plaintext").unwrap();

        let r1 = vault.get_secret(&[0x01u8; 16]).unwrap();
        let r2 = vault.get_secret(&[0x02u8; 16]).unwrap();
        assert_eq!(r1, b"same plaintext");
        assert_eq!(r2, b"same plaintext");
    }

    #[test]
    fn lock_prevents_operations() {
        let mut vault = unlocked_vault();
        vault.add_secret([0x01u8; 16], b"secret").unwrap();
        vault.lock();
        assert!(!vault.is_unlocked());
        assert!(vault.get_secret(&[0x01u8; 16]).is_err());
    }

    #[test]
    fn lock_then_unlock_recycles_vek() {
        let mut vault = unlocked_vault();
        let wrapped = vault.wrapped_vek().unwrap();
        vault.add_secret([0x01u8; 16], b"persisted secret").unwrap();
        vault.lock();
        assert!(!vault.is_unlocked());

        // Replay unlock with the same password + wrapped VEK.
        vault.unlock("correct horse battery staple", &wrapped).unwrap();
        assert!(vault.is_unlocked());
        let rec = vault.get_secret(&[0x01u8; 16]).unwrap();
        assert_eq!(rec, b"persisted secret");
    }

    #[test]
    fn wrong_password_fails_unlock() {
        let mut vault = unlocked_vault();
        let wrapped = vault.wrapped_vek().unwrap();
        vault.lock();
        assert!(matches!(
            vault.unlock("wrong password", &wrapped),
            Err(crate::Error::AuthenticationFailed)
        ));
    }

    #[test]
    fn remove_secret() {
        let mut vault = unlocked_vault();
        let id = [0x01u8; 16];
        vault.add_secret(id, b"temp").unwrap();
        assert_eq!(vault.record_count(), 1);
        vault.remove_secret(&id).unwrap();
        assert_eq!(vault.record_count(), 0);
    }

    #[test]
    fn get_nonexistent_record_errors() {
        let vault = unlocked_vault();
        assert!(vault.get_secret(&[0xFFu8; 16]).is_err());
    }

    #[test]
    fn different_vaults_different_salts() {
        let v1 = Vault::create("same password").unwrap();
        let v2 = Vault::create("same password").unwrap();
        assert_ne!(v1.salt(), v2.salt());
    }
}
