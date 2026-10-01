//! WASM bindings for `vault-core`.
//!
//! Exposes vault operations — create, unlock, lock, CRUD, password gen, TOTP —
//! as JavaScript functions via `wasm-bindgen`.
//!
//! # Persistence Model
//!
//! The encrypted vault lives as a `Uint8Array` in JS land. WASM never
//! touches the filesystem. The JavaScript host is responsible for storage
//! (IndexedDB, OPFS, localStorage, etc.).

use std::collections::HashMap;
use std::sync::Mutex;
use vault_core::{
    aead::{decrypt_record, encrypt_record, Ciphertext},
    dek::derive_dek,
    format::{deserialize_records, parse_header, serialize_header, serialize_records},
    kdf::{derive_kek, KdfParams},
    types::KeyBytes,
    vek::Vek,
};
use wasm_bindgen::prelude::*;

// Re-export types from vault-sdk
pub use vault_sdk::password::{self, CharClass, PasswordPolicy, Strength};
pub use vault_sdk::recovery::{self, RecoveryPhrase};
pub use vault_sdk::totp::{self, TotpConfig};

// ─── In-Memory Vault State ─────────────────────────────────────────────────

struct VaultState {
    vek: Vek,
    kdf_params: KdfParams,
    salt: [u8; 32],
    records: HashMap<[u8; 16], Ciphertext>,
}

static VAULT: Mutex<Option<VaultState>> = Mutex::new(None);

// ─── Helpers ───────────────────────────────────────────────────────────────

fn into_js_err(e: impl std::fmt::Display) -> JsValue {
    JsError::new(&format!("{e}")).into()
}

fn require_unlocked() -> Result<std::sync::MutexGuard<'static, Option<VaultState>>, JsValue> {
    let guard = VAULT.lock().expect("vault mutex poisoned");
    if guard.is_some() {
        Ok(guard)
    } else {
        Err(JsError::new("vault is locked").into())
    }
}

fn hex_to_id(hex: &str) -> Result<[u8; 16], JsValue> {
    let bytes = hex::decode(hex)
        .map_err(|e| JsValue::from(JsError::new(&format!("invalid hex: {e}"))))?;
    if bytes.len() != 16 {
        return Err(JsError::new("record id must be 32 hex chars (16 bytes)").into());
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn parse_salt(salt: &[u8]) -> Result<[u8; 32], JsValue> {
    if salt.len() != 32 {
        return Err(JsError::new("salt must be 32 bytes").into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(salt);
    Ok(arr)
}

// ─── KEK Derivation ────────────────────────────────────────────────────────

/// Derive a KEK from a password + salt + KDF parameters.
#[wasm_bindgen]
pub fn derive_kek_bytes(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Vec<u8>, JsValue> {
    let salt_arr = parse_salt(salt)?;
    let params = KdfParams { m_cost, t_cost, p_cost };
    params.validate().map_err(into_js_err)?;
    let kek = derive_kek(password, &salt_arr, params).map_err(into_js_err)?;
    Ok(kek.into_bytes().to_vec())
}

// ─── Create Vault ─────────────────────────────────────────────────────────

/// Create a new vault and return the serialized vault bytes.
///
/// JS host must persist the returned bytes.
#[wasm_bindgen]
pub fn create_vault(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Vec<u8>, JsValue> {
    let salt_arr = parse_salt(salt)?;
    let params = KdfParams { m_cost, t_cost, p_cost };
    params.validate().map_err(into_js_err)?;

    let kek = derive_kek(password, &salt_arr, params).map_err(into_js_err)?;
    let vek = Vek::random();
    let wrapped_vek = vek.wrap(&kek).map_err(into_js_err)?;

    let header = serialize_header(params, &salt_arr, &wrapped_vek);
    let records_blob = serialize_records(&[]);

    let mut bytes = header;
    bytes.extend_from_slice(&records_blob);

    let mut guard = require_unlocked()?;
    *guard = Some(VaultState {
        vek,
        kdf_params: params,
        salt: salt_arr,
        records: HashMap::new(),
    });

    Ok(bytes)
}

// ─── Unlock Vault ─────────────────────────────────────────────────────────

/// Unlock a vault from its encrypted bytes + password.
#[wasm_bindgen]
pub fn unlock_vault(vault_bytes: &[u8], password: &str) -> Result<(), JsValue> {
    if vault_bytes.len() < vault_core::format::HEADER_SIZE {
        return Err(JsValue::from(JsError::new("vault bytes too short — not a valid vault file")));
    }

    let header_bytes = &vault_bytes[..vault_core::format::HEADER_SIZE];
    let (kdf_params, salt, wrapped_vek) = parse_header(header_bytes)
        .map_err(into_js_err)?;

    let kek = derive_kek(password, &salt, kdf_params).map_err(into_js_err)?;
    let vek = wrapped_vek.unwrap(&kek).map_err(into_js_err)?;

    let body_bytes = &vault_bytes[vault_core::format::HEADER_SIZE..];
    let decrypted = deserialize_records(body_bytes).map_err(into_js_err)?;

    let records: HashMap<[u8; 16], Ciphertext> = decrypted.into_iter().collect();

    let mut guard = require_unlocked()?;
    *guard = Some(VaultState {
        vek,
        kdf_params,
        salt,
        records,
    });

    Ok(())
}

// ─── Lock Vault ────────────────────────────────────────────────────────────

/// Lock the vault — zeroizes all in-memory decrypted state.
#[wasm_bindgen]
pub fn lock_vault() {
    let mut guard = VAULT.lock().expect("vault mutex poisoned");
    guard.take();
}

/// Whether a vault is currently unlocked in memory.
#[wasm_bindgen]
pub fn is_unlocked() -> bool {
    let guard = VAULT.lock().expect("vault mutex poisoned");
    guard.is_some()
}

/// Number of records in the unlocked vault.
#[wasm_bindgen]
pub fn record_count() -> Result<u32, JsValue> {
    let guard = require_unlocked()?;
    Ok(guard.as_ref().unwrap().records.len() as u32)
}

// ─── Record CRUD ───────────────────────────────────────────────────────────

/// List all record IDs as hex strings.
#[wasm_bindgen]
pub fn list_records() -> Result<Vec<String>, JsValue> {
    let guard = require_unlocked()?;
    let state = guard.as_ref().unwrap();
    Ok(state.records.keys().map(hex::encode).collect())
}

/// Get the decrypted value of a record (returns Uint8Array of plaintext).
#[wasm_bindgen]
pub fn get_record(id_hex: &str) -> Result<Vec<u8>, JsValue> {
    let id = hex_to_id(id_hex)?;
    let guard = require_unlocked()?;
    let state = guard.as_ref().unwrap();

    let ciphertext = state.records.get(&id)
        .ok_or_else(|| JsValue::from(JsError::new("record not found")))?;

    let dek = derive_dek(state.vek.as_key_bytes(), &id).map_err(into_js_err)?;
    decrypt_record(dek.as_key_bytes(), ciphertext).map_err(into_js_err)
}

/// Set a record — encrypts `value` under the VEK-derived DEK.
#[wasm_bindgen]
pub fn set_record(id_hex: &str, value: &[u8]) -> Result<(), JsValue> {
    let id = hex_to_id(id_hex)?;
    let mut guard = require_unlocked()?;
    let state = guard.as_mut().unwrap();

    let dek = derive_dek(state.vek.as_key_bytes(), &id).map_err(into_js_err)?;
    let ciphertext = encrypt_record(dek.as_key_bytes(), value).map_err(into_js_err)?;
    state.records.insert(id, ciphertext);
    Ok(())
}

/// Delete a record by ID.
#[wasm_bindgen]
pub fn delete_record(id_hex: &str) -> Result<(), JsValue> {
    let id = hex_to_id(id_hex)?;
    let mut guard = require_unlocked()?;
    let state = guard.as_mut().unwrap();
    state.records.remove(&id);
    Ok(())
}

/// Generate a random 16-byte record ID, returned as 32-character hex string.
#[wasm_bindgen]
pub fn new_record_id() -> String {
    let mut id = [0u8; 16];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut id);
    hex::encode(id)
}

// ─── Save Vault ────────────────────────────────────────────────────────────

/// Serialize the current vault state to bytes for JS to persist.
///
/// NOTE: The VEK is wrapped with a placeholder key here. For a real save
/// after unlocking, the host should keep the original vault bytes
/// (which contain the wrapped_vek produced from the master password).
/// Use `save_vault_with_password` for password rotation.
#[wasm_bindgen]
pub fn save_vault() -> Result<Vec<u8>, JsValue> {
    let guard = require_unlocked()?;
    let state = guard.as_ref().unwrap();

    let placeholder_kek = KeyBytes::new([0u8; 32]);
    let wrapped_vek = state.vek.wrap(&placeholder_kek).map_err(into_js_err)?;
    let header = serialize_header(state.kdf_params, &state.salt, &wrapped_vek);

    let record_pairs: Vec<([u8; 16], Ciphertext)> = state.records
        .iter()
        .map(|(&id, ct)| (id, ct.clone()))
        .collect();
    let records_blob = serialize_records(&record_pairs);

    let mut bytes = header;
    bytes.extend_from_slice(&records_blob);
    Ok(bytes)
}

/// Save vault with a new password (key rotation).
#[wasm_bindgen]
pub fn save_vault_with_password(
    new_password: &str,
    new_salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Vec<u8>, JsValue> {
    let salt_arr = parse_salt(new_salt)?;
    let guard = require_unlocked()?;
    let state = guard.as_ref().unwrap();

    let params = KdfParams { m_cost, t_cost, p_cost };
    params.validate().map_err(into_js_err)?;

    let new_kek = derive_kek(new_password, &salt_arr, params).map_err(into_js_err)?;
    let wrapped_vek = state.vek.wrap(&new_kek).map_err(into_js_err)?;
    let header = serialize_header(params, &salt_arr, &wrapped_vek);

    let record_pairs: Vec<([u8; 16], Ciphertext)> = state.records
        .iter()
        .map(|(&id, ct)| (id, ct.clone()))
        .collect();
    let records_blob = serialize_records(&record_pairs);

    let mut bytes = header;
    bytes.extend_from_slice(&records_blob);
    Ok(bytes)
}

// ─── Password Generator ────────────────────────────────────────────────────

/// Generate a cryptographically secure random password.
#[wasm_bindgen]
pub fn generate_password(
    length: u32,
    uppercase: bool,
    lowercase: bool,
    digits: bool,
    symbols: bool,
    avoid_ambiguous: bool,
) -> Result<String, JsValue> {
    let mut classes = Vec::new();
    if lowercase { classes.push(CharClass::Lowercase); }
    if uppercase { classes.push(CharClass::Uppercase); }
    if digits { classes.push(CharClass::Digits); }
    if symbols { classes.push(CharClass::Symbols); }

    if classes.is_empty() {
        return Err(JsValue::from(JsError::new("must enable at least one character class")));
    }

    let policy = PasswordPolicy {
        length: length as usize,
        classes,
        avoid_ambiguous,
    };
    vault_sdk::password::generate(&policy).map_err(into_js_err)
}

/// Estimate entropy in bits for a password with the given parameters.
#[wasm_bindgen]
pub fn password_entropy_bits(
    length: u32,
    uppercase: bool,
    lowercase: bool,
    digits: bool,
    symbols: bool,
    avoid_ambiguous: bool,
) -> f64 {
    let mut classes = Vec::new();
    if lowercase { classes.push(CharClass::Lowercase); }
    if uppercase { classes.push(CharClass::Uppercase); }
    if digits { classes.push(CharClass::Digits); }
    if symbols { classes.push(CharClass::Symbols); }

    let policy = PasswordPolicy { length: length as usize, classes, avoid_ambiguous };
    vault_sdk::password::entropy_bits(&policy)
}

/// Compute strength level ("Weak"/"Fair"/"Strong"/"VeryStrong") for given entropy.
#[wasm_bindgen]
pub fn password_strength(entropy_bits: f64) -> String {
    Strength::from_entropy(entropy_bits).label().to_string()
}

// ─── TOTP ──────────────────────────────────────────────────────────────────

/// Generate a 6-digit TOTP code from a base32 secret.
#[wasm_bindgen]
pub fn generate_totp(secret: &str) -> Result<u32, JsValue> {
    let config = vault_sdk::totp::TotpConfig::from_secret_b32(secret, 30, 6)
        .map_err(into_js_err)?;
    vault_sdk::totp::generate(&config).map_err(into_js_err)
}

/// Validate a TOTP code. Returns true if valid (with ±1 step tolerance).
#[wasm_bindgen]
pub fn validate_totp(secret: &str, code: u32) -> Result<bool, JsValue> {
    let config = vault_sdk::totp::TotpConfig::from_secret_b32(secret, 30, 6)
        .map_err(into_js_err)?;
    vault_sdk::totp::validate(&config, code).map_err(into_js_err)
}

// ─── Utility ───────────────────────────────────────────────────────────────

/// Generate random bytes.
#[wasm_bindgen]
pub fn random_bytes(len: u32) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; len as usize];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

/// HMAC-SHA256(key, data) → 32 bytes.
#[wasm_bindgen]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// SHA-256(data) → 32 bytes.
#[wasm_bindgen]
pub fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

/// Constant-time comparison of two byte slices.
#[wasm_bindgen]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    vault_core::crypto::constant_time_eq(a, b)
}

/// Convert bytes to hex string.
#[wasm_bindgen]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// Convert hex string to bytes.
#[wasm_bindgen]
pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, JsValue> {
    hex::decode(hex).map_err(into_js_err)
}

// ─── Recovery Phrase ─────────────────────────────────────────────────────

/// Generate a random 8-word recovery phrase (BIP-39 vocabulary).
///
/// Returns a space-separated string of 8 words derived from OS CSPRNG entropy.
/// The user must write these down — they are the only way to recover the vault
/// without the master password.
#[wasm_bindgen]
pub fn recovery_generate() -> Result<String, JsValue> {
    let phrase = recovery::generate_phrase();
    Ok(phrase.phrase())
}

/// Verify that a recovery phrase string is well-formed (all words valid, 8 words).
#[wasm_bindgen]
pub fn recovery_verify(phrase_str: &str) -> Result<bool, JsValue> {
    let phrase = recovery::parse_phrase(phrase_str).map_err(into_js_err)?;
    Ok(recovery::validate_phrase(&phrase).is_ok())
}

/// Convert a recovery phrase back to entropy bytes (32 bytes as hex).
///
/// This is used during vault recovery: the user enters their phrase, and the
/// entropy is used to re-derive the vault's master key material.
#[wasm_bindgen]
pub fn recovery_to_entropy(phrase_str: &str) -> Result<String, JsValue> {
    let phrase = recovery::parse_phrase(phrase_str).map_err(into_js_err)?;
    let entropy = recovery::phrase_to_entropy(&phrase).map_err(into_js_err)?;
    Ok(hex::encode(entropy))
}

// ─── Init ──────────────────────────────────────────────────────────────────

#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}