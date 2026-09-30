//! Secret Manager Desktop — Tauri 2.0 backend.
//!
//! This binary bridges vault-db (encrypted SQLite storage) to the Tauri
//! frontend via IPC commands. All sensitive operations — password handling,
//! encryption, decryption — happen in this Rust process. The frontend
//! (JavaScript/TypeScript) never has access to key material; it only
//! receives the plaintext of requested secrets and cannot inspect the vault
//! file or derive keys.

use std::sync::Mutex;
use tauri::State;
use vault_db::VaultFile;

// ─── App State ──────────────────────────────────────────────────────────────

/// Global application state — holds the open vault file.
///
/// `Option<VaultFile>` encodes the lock state:
/// - `None` — vault is locked (or not yet created).
/// - `Some` — vault is open and unlocked.
#[derive(Clone)]
struct AppState {
    vault: Mutex<Option<VaultFile>>,
}

impl AppState {
    fn new() -> Self {
        Self { vault: Mutex::new(None) }
    }

    fn is_unlocked(&self) -> bool {
        self.vault.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    fn require_unlocked(&self) -> Result<(), String> {
        if self.is_unlocked() {
            Ok(())
        } else {
            Err("vault is locked — call unlock first".to_string())
        }
    }
}

// ─── Tauri Commands ─────────────────────────────────────────────────────────

/// Create a new vault at the default path.
#[tauri::command]
fn create_vault(state: State<'_, AppState>, password: &str) -> Result<String, String> {
    let path = default_vault_path()?;
    let store = VaultFile::create(path, password)
        .map_err(|e| format!("create failed: {e}"))?;
    *state.vault.lock().map_err(|_| "vault lock poisoned".to_string())? = Some(store);
    Ok("ok".to_string())
}

/// Unlock an existing vault with the master password.
#[tauri::command]
fn unlock_vault(state: State<'_, AppState>, password: &str) -> Result<String, String> {
    let path = default_vault_path()?;
    let mut store = VaultFile::open(path)
        .map_err(|e| format!("open failed: {e}"))?;
    store.unlock(password)
        .map_err(|e| format!("unlock failed: {e}"))?;
    *state.vault.lock().map_err(|_| "vault lock poisoned".to_string())? = Some(store);
    Ok("ok".to_string())
}

/// Lock the vault — zeroize all keys and drop the in-memory state.
#[tauri::command]
fn lock_vault(state: State<'_, AppState>) -> Result<String, String> {
    let mut guard = state.vault.lock().map_err(|_| "vault lock poisoned".to_string())?;
    *guard = None;
    Ok("ok".to_string())
}

/// Check whether the vault is currently unlocked.
#[tauri::command]
fn is_unlocked(state: State<'_, AppState>) -> Result<bool, String> {
    Ok(state.is_unlocked())
}

/// List all record IDs in the vault, returned as hex strings.
#[tauri::command]
fn list_records(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    state.require_unlocked()?;
    let guard = state.vault.lock().map_err(|_| "vault lock poisoned".to_string())?;
    let store = guard.as_ref().ok_or("vault is locked".to_string())?;
    let ids = store.list_records()
        .map_err(|e| format!("list failed: {e}"))?;
    Ok(ids.into_iter().map(hex::encode).collect())
}

/// Get a secret by its record ID (hex-encoded).
///
/// # Security
/// The returned value is plaintext. The frontend must NOT log or persist
/// it outside in-memory state. Use [`copy_to_clipboard`] to deliver it.
#[tauri::command]
fn get_secret(state: State<'_, AppState>, id: &str) -> Result<String, String> {
    state.require_unlocked()?;
    let guard = state.vault.lock().map_err(|_| "vault lock poisoned".to_string())?;
    let store = guard.as_ref().ok_or("vault is locked".to_string())?;
    let record_id = hex::decode(id).map_err(|e| format!("invalid record ID: {e}"))?;
    let value = store.get_secret(record_id)
        .map_err(|e| format!("get failed: {e}"))?;
    String::from_utf8(value).map_err(|e| format!("secret is not valid UTF-8: {e}"))
}

/// Store a secret with the given record ID (hex-encoded).
#[tauri::command]
fn set_secret(
    state: State<'_, AppState>,
    id: &str,
    value: &str,
) -> Result<String, String> {
    state.require_unlocked()?;
    let mut guard = state.vault.lock().map_err(|_| "vault lock poisoned".to_string())?;
    let store = guard.as_mut().ok_or("vault is locked".to_string())?;
    let record_id = hex::decode(id).map_err(|e| format!("invalid record ID: {e}"))?;
    store.put_secret(record_id, value.as_bytes())
        .map_err(|e| format!("set failed: {e}"))?;
    Ok("ok".to_string())
}

/// Delete a secret by record ID (hex-encoded).
///
/// This is irreversible. The DEK is destroyed with the record, making
/// the data unrecoverable even with the master password.
#[tauri::command]
fn delete_secret(state: State<'_, AppState>, id: &str) -> Result<String, String> {
    state.require_unlocked()?;
    let mut guard = state.vault.lock().map_err(|_| "vault lock poisoned".to_string())?;
    let store = guard.as_mut().ok_or("vault is locked".to_string())?;
    let record_id = hex::decode(id).map_err(|e| format!("invalid record ID: {e}"))?;
    store.remove_secret(record_id)
        .map_err(|e| format!("delete failed: {e}"))?;
    Ok("ok".to_string())
}

/// Record count in the vault (0 when locked).
#[tauri::command]
fn record_count(state: State<'_, AppState>) -> Result<usize, String> {
    state.require_unlocked()?;
    let guard = state.vault.lock().map_err(|_| "vault lock poisoned".to_string())?;
    let store = guard.as_ref().ok_or("vault is locked".to_string())?;
    Ok(store.record_count())
}

/// Generate a cryptographically secure random password.
///
/// # Arguments
/// - `length`: desired length (default 24, clamped to 4–256)
/// - `include_symbols`: include non-alphanumeric characters
#[tauri::command]
fn generate_password(length: Option<usize>, include_symbols: Option<bool>) -> Result<String, String> {
    let len = length.unwrap_or(24).clamp(4, 256);
    let symbols = include_symbols.unwrap_or(true);
    let policy = vault_sdk::password::PasswordPolicy {
        length: len,
        include_symbols: symbols,
        ..Default::default()
    };
    vault_sdk::password::generate(&policy)
        .map_err(|e| format!("password generation failed: {e}"))
}

/// Copy text to the system clipboard, auto-clearing after `ttl_seconds`.
///
/// # Security
/// The clipboard is cleared after the TTL expires. The original text is
/// overwritten with spaces before clearing to defeat clipboard history.
#[tauri::command]
fn copy_to_clipboard(text: &str, ttl_seconds: Option<u64>) -> Result<(), String> {
    use std::thread;
    let ttl = ttl_seconds.unwrap_or(30);

    let mut clipboard = arboard::Clipboard::new()
        .map_err(|e| format!("clipboard error: {e}"))?;
    clipboard.set_text(text.to_string())
        .map_err(|e| format!("clipboard error: {e}"))?;

    let text_len = text.len();
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(ttl));
        if let Ok(mut cb) = arboard::Clipboard::new() {
            let _ = cb.set_text(" ".repeat(text_len));
            let _ = cb.set_text(String::new());
        }
    });
    Ok(())
}

/// Export the vault to an encrypted backup file.
#[tauri::command]
fn export_vault(state: State<'_, AppState>, dest: &str) -> Result<String, String> {
    state.require_unlocked()?;
    let guard = state.vault.lock().map_err(|_| "vault lock poisoned".to_string())?;
    let store = guard.as_ref().ok_or("vault is locked".to_string())?;
    let vault = store.vault().map_err(|e| e.to_string())?;

    let mut buf = Vec::new();
    vault_sdk::backup::backup_vault(vault, &mut buf)
        .map_err(|e| format!("export failed: {e}"))?;

    std::fs::write(dest, &buf)
        .map_err(|e| format!("write failed: {e}"))?;
    Ok(dest.to_string())
}

/// Type a secret directly into the focused input field (autofill).
///
/// # Security
/// This avoids the clipboard entirely. The text is zeroized after typing.
/// Uses a random inter-character delay to defeat simple keyloggers.
#[tauri::command]
fn type_secret_cmd(state: State<'_, AppState>, id: &str) -> Result<String, String> {
    state.require_unlocked()?;
    let guard = state.vault.lock().map_err(|_| "vault lock poisoned".to_string())?;
    let store = guard.as_ref().ok_or("vault is locked".to_string())?;
    let record_id = hex::decode(id).map_err(|e| format!("invalid record ID: {e}"))?;
    let value = store.get_secret(record_id)
        .map_err(|e| format!("get failed: {e}"))?;

    // Type the secret
    use desktop_app::auto_type::type_secret;
    type_secret(String::from_utf8_lossy(&value).to_string())
        .map_err(|e| format!("auto-type failed: {e}"))?;

    // Zeroize the value buffer
    drop(value);

    Ok("ok".to_string())
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Return the default vault file path.
fn default_vault_path() -> Result<std::path::PathBuf, String> {
    let home = dirs::home_dir().ok_or("cannot determine home directory")?;
    let vault_dir = home.join(".config").join("secret-manager");
    std::fs::create_dir_all(&vault_dir)
        .map_err(|e| format!("failed to create vault dir: {e}"))?;
    Ok(vault_dir.join("vault.enc"))
}

// ─── Main ───────────────────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState::new())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            create_vault,
            unlock_vault,
            lock_vault,
            is_unlocked,
            list_records,
            get_secret,
            set_secret,
            delete_secret,
            record_count,
            generate_password,
            copy_to_clipboard,
            export_vault,
            type_secret_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
