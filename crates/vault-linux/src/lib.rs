//! Linux platform crate for the Secret Manager vault.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use vault_core::ffi::{KeyStore, Platform, SecureInput, SessionPersistence, SystemClipboard};
use vault_core::session::SessionToken;
use vault_core::vek::WrappedVek;
use vault_core::{Error, Result};

use thiserror::Error;

// ─── Errors ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum LinuxError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("clipboard error: {0}")]
    Clipboard(String),
}

impl From<LinuxError> for Error {
    fn from(e: LinuxError) -> Self {
        match e {
            LinuxError::Io(e) => Error::Storage(e.to_string()),
            LinuxError::Utf8(e) => Error::Storage(e.to_string()),
            LinuxError::Clipboard(e) => Error::Storage(e),
        }
    }
}

// ─── Linux Key Store ─────────────────────────────────────────────────────

#[derive(Clone)]
pub struct LinuxKeyStore {
    base_dir: PathBuf,
}

impl Default for LinuxKeyStore {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self {
            base_dir: PathBuf::from(home).join(".config").join("secret-manager").join("keys"),
        }
    }
}

impl LinuxKeyStore {
    pub fn new() -> Self {
        Self::default()
    }
    fn path_for(&self, name: &str) -> PathBuf {
        self.base_dir.join(name)
    }
}

impl KeyStore for LinuxKeyStore {
    fn store(&self, name: &str, data: &[u8]) -> Result<()> {
        let path = self.path_for(name);
        std::fs::create_dir_all(&path.parent().unwrap())?;
        std::fs::write(&path, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
        }
        Ok(())
    }

    fn retrieve(&self, name: &str) -> Result<Vec<u8>> {
        let path = self.path_for(name);
        std::fs::read(&path).map_err(|e| Error::Storage(e.to_string()))
    }

    fn delete(&self, name: &str) -> Result<()> {
        let path = self.path_for(name);
        std::fs::remove_file(&path).map_err(|e| Error::Storage(e.to_string()))
    }

    fn contains(&self, name: &str) -> bool {
        self.path_for(name).exists()
    }
}

// ─── Linux Secure Input ──────────────────────────────────────────────────

#[derive(Clone)]
pub struct LinuxSecureInput;

impl Default for LinuxSecureInput {
    fn default() -> Self { Self }
}

impl SecureInput for LinuxSecureInput {
    fn prompt_password(&self, prompt: &str) -> Result<String> {
        use std::io::{Read, Write};
        let mut tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|e| Error::Storage(format!("cannot open /dev/tty: {e}")))?;
        tty.write_all(prompt.as_bytes()).map_err(|e| Error::Storage(e.to_string()))?;
        let mut buf = String::new();
        tty.read_to_string(&mut buf)
            .map_err(|e| Error::Storage(format!("read error: {e}")))?;
        Ok(buf.trim().to_string())
    }

    fn confirm_password(&self, prompt: &str, expected: &str) -> Result<bool> {
        let entered = self.prompt_password(prompt)?;
        Ok(entered == expected)
    }
}

// ─── Linux Clipboard ─────────────────────────────────────────────────────

#[derive(Clone)]
pub struct LinuxClipboard;

impl Default for LinuxClipboard {
    fn default() -> Self { Self }
}

impl SystemClipboard for LinuxClipboard {
    fn copy(&self, text: &str) -> Result<()> {
        let result = Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(std::process::Stdio::piped())
            .spawn();
        match result {
            Ok(mut child) => {
                use std::io::Write;
                if let Some(mut stdin) = child.stdin.take() {
                    stdin.write_all(text.as_bytes()).ok();
                }
                let _ = child.wait();
                Ok(())
            }
            Err(_) => {
                let result = Command::new("xsel")
                    .args(["--input", "--clipboard"])
                    .stdin(std::process::Stdio::piped())
                    .spawn();
                match result {
                    Ok(mut child) => {
                        use std::io::Write;
                        if let Some(mut stdin) = child.stdin.take() {
                            stdin.write_all(text.as_bytes()).ok();
                        }
                        let _ = child.wait();
                        Ok(())
                    }
                    Err(e) => Err(Error::Storage(format!("clipboard failed: {e}"))),
                }
            }
        }
    }

    fn paste(&self) -> Result<String> {
        let output = Command::new("xclip")
            .args(["-selection", "clipboard", "-o"])
            .output()
            .or_else(|_| Command::new("xsel").args(["--output", "--clipboard"]).output())
            .map_err(|e| Error::Storage(format!("clipboard read failed: {e}")))?;
        String::from_utf8(output.stdout)
            .map_err(|e| Error::Storage(format!("UTF-8 error: {e}")))
    }

    fn clear(&self) -> Result<()> {
        let _ = Command::new("xclip")
            .args(["-selection", "clipboard", "-i"])
            .stdin(std::process::Stdio::null())
            .status();
        let _ = Command::new("xsel")
            .args(["--clear", "--clipboard"])
            .status();
        Ok(())
    }
}

// ─── Linux Session Persistence ──────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct StoredToken {
    token_id: [u8; 16],
    expires_at_secs: u64,
    wrapped_vek_bytes: Vec<u8>,
}

#[derive(Clone)]
pub struct LinuxSessionPersistence {
    session_dir: PathBuf,
}

impl Default for LinuxSessionPersistence {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self {
            session_dir: PathBuf::from(home).join(".config").join("secret-manager").join("sessions"),
        }
    }
}

impl LinuxSessionPersistence {
    pub fn new() -> Self { Self::default() }
    fn path_for(&self, service: &str, account: &str) -> PathBuf {
        self.session_dir.join(format!("{}_{}", service, account))
    }
}

impl SessionPersistence for LinuxSessionPersistence {
    fn save_token(&self, service: &str, account: &str, token: &SessionToken) -> Result<()> {
        let path = self.path_for(service, account);
        std::fs::create_dir_all(&path.parent().unwrap())?;
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let stored = StoredToken {
            token_id: *token.token_id(),
            expires_at_secs: now_secs + token.time_remaining().map(|d| d.as_secs()).unwrap_or(0),
            wrapped_vek_bytes: token.wrapped_vek().to_bytes(),
        };
        // Manual JSON encoding without serde_json dependency
        let data = format!(
            "{{\"token_id\":\"{}\",\"expires_at_secs\":{},\"wrapped_vek_bytes\":\"{}\"}}",
            hex_encode(&stored.token_id),
            stored.expires_at_secs,
            base64_encode(&stored.wrapped_vek_bytes)
        );
        std::fs::write(&path, data)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&path, perms)?;
        }
        Ok(())
    }

    fn load_token(&self, service: &str, account: &str) -> Result<Option<SessionToken>> {
        let path = self.path_for(service, account);
        if !path.exists() { return Ok(None); }
        let raw = std::fs::read_to_string(&path).map_err(|e| Error::Storage(e.to_string()))?;
        let stored = parse_stored_token(&raw).ok_or_else(|| Error::Storage("parse error".into()))?;
        if stored.expires_at_secs == 0 || std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) > stored.expires_at_secs {
            let _ = std::fs::remove_file(&path);
            return Ok(None);
        }
        let wvek = WrappedVek::from_bytes(&stored.wrapped_vek_bytes)
            .map_err(|e| Error::Storage(e.to_string()))?;
        let ttl = std::time::Duration::from_secs(stored.expires_at_secs.saturating_sub(
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
        ));
        Ok(Some(SessionToken::new(wvek, ttl)))
    }

    fn delete_token(&self, service: &str, account: &str) -> Result<()> {
        std::fs::remove_file(self.path_for(service, account)).ok();
        Ok(())
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .filter_map(|c| {
            let h = (c[0] as char).to_digit(16)?;
            let l = if c.len() > 1 { (c[1] as char).to_digit(16)? } else { 0 };
            Some(((h << 4) | l) as u8)
        })
        .collect()
}

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let bytes = data;
    for chunk in bytes.chunks(3) {
        let mut buf = [0u8; 3];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = (buf[0] as u32) << 16 | (buf[1] as u32) << 8 | buf[2] as u32;
        result.push(BASE64_CHARS[((n >> 18) & 0x3F) as usize] as char);
        result.push(BASE64_CHARS[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(BASE64_CHARS[((n >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(BASE64_CHARS[(n & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

fn base64_decode(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let chars: Vec<u8> = s.bytes().filter(|&b| b != b'=' && b != b'\n').collect();
    for chunk in chars.chunks(4) {
        let mut vals = [0u32; 4];
        for (i, &c) in chunk.iter().enumerate() {
            vals[i] = match c {
                b'A'..=b'Z' => (c - b'A') as u32,
                b'a'..=b'z' => (c - b'a' + 26) as u32,
                b'0'..=b'9' => (c - b'0' + 52) as u32,
                b'+' => 62,
                b'/' => 63,
                _ => 0,
            };
        }
        let n = (vals[0] << 18) | (vals[1] << 12) | (vals[2] << 6) | vals[3];
        result.push((n >> 16) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' { result.push((n >> 8) as u8); }
        if chunk.len() > 3 && chunk[3] != b'=' { result.push(n as u8); }
    }
    result
}

fn parse_stored_token(s: &str) -> Option<StoredToken> {
    // Simple manual JSON parser for our specific format
    let mut token_id = [0u8; 16];
    let mut expires_at_secs = 0u64;
    let mut wrapped_bytes = Vec::new();

    // Extract token_id hex
    if let Some(start) = s.find("\"token_id\":\"") {
        let start = start + 12;
        if let Some(end) = s[start..].find('"') {
            let hex_str = &s[start..start + end];
            let decoded = hex_decode(hex_str);
            if decoded.len() == 16 {
                token_id.copy_from_slice(&decoded);
            }
        }
    }

    // Extract expires_at_secs
    if let Some(start) = s.find("\"expires_at_secs\":") {
        let start = start + 19;
        if let Some(end) = s[start..].find(|c: char| !c.is_ascii_digit()) {
            let num_str = &s[start..start + end];
            expires_at_secs = num_str.parse().unwrap_or(0);
        }
    }

    // Extract wrapped_vek_bytes base64
    if let Some(start) = s.find("\"wrapped_vek_bytes\":\"") {
        let start = start + 22;
        if let Some(end) = s[start..].find('"') {
            let b64 = &s[start..start + end];
            wrapped_bytes = base64_decode(b64);
        }
    }

    Some(StoredToken { token_id, expires_at_secs, wrapped_vek_bytes: wrapped_bytes })
}

// ─── Linux Platform ──────────────────────────────────────────────────────

pub struct LinuxPlatform {
    key_store: LinuxKeyStore,
    secure_input: LinuxSecureInput,
    clipboard: LinuxClipboard,
    session_persistence: LinuxSessionPersistence,
}

impl Default for LinuxPlatform {
    fn default() -> Self { Self::new() }
}

impl LinuxPlatform {
    pub fn new() -> Self {
        Self {
            key_store: LinuxKeyStore::default(),
            secure_input: LinuxSecureInput::default(),
            clipboard: LinuxClipboard::default(),
            session_persistence: LinuxSessionPersistence::default(),
        }
    }
}

impl Platform for LinuxPlatform {
    fn key_store(&self) -> Arc<dyn KeyStore> {
        Arc::new(self.key_store.clone())
    }
    fn secure_input(&self) -> Arc<dyn SecureInput> {
        Arc::new(self.secure_input.clone())
    }
    fn clipboard(&self) -> Arc<dyn SystemClipboard> {
        Arc::new(self.clipboard.clone())
    }
    fn session_persistence(&self) -> Arc<dyn SessionPersistence> {
        Arc::new(self.session_persistence.clone())
    }
}
