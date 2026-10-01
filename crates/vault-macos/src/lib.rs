//! macOS platform crate for the Secret Manager vault.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use vault_core::ffi::{KeyStore, Platform, SecureInput, SessionPersistence, SystemClipboard};
use vault_core::session::SessionToken;
use vault_core::vek::WrappedVek;
use vault_core::{Error, Result};

use thiserror::Error;

// --- Errors ---

#[derive(Debug, Error)]
pub enum MacError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

impl From<MacError> for Error {
    fn from(e: MacError) -> Self {
        match e {
            MacError::Io(e) => Error::Storage(e.to_string()),
            MacError::Utf8(e) => Error::Storage(e.to_string()),
        }
    }
}

// --- Helpers ---

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Vec<u8> {
    s.as_bytes().chunks(2).filter_map(|c| {
        let h = (c[0] as char).to_digit(16)?;
        let l = if c.len() > 1 { (c[1] as char).to_digit(16)? } else { 0 };
        Some(((h << 4) | l) as u8)
    }).collect()
}

fn base64_encode(data: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let mut buf = [0u8; 3];
        buf[..chunk.len()].copy_from_slice(chunk);
        let n = (buf[0] as u32) << 16 | (buf[1] as u32) << 8 | buf[2] as u32;
        result.push(CHARS[((n >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 { result.push(CHARS[((n >> 6) & 0x3F) as usize] as char); } else { result.push('='); }
        if chunk.len() > 2 { result.push(CHARS[(n & 0x3F) as usize] as char); } else { result.push('='); }
    }
    result
}

fn base64_decode(s: &str) -> Vec<u8> {
    let mut r = Vec::new();
    let chars: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    for chunk in chars.chunks(4) {
        let mut v = [0u32; 4];
        for (i, &c) in chunk.iter().enumerate() {
            v[i] = match c {
                b'A'..=b'Z' => (c - b'A') as u32,
                b'a'..=b'z' => (c - b'a' + 26) as u32,
                b'0'..=b'9' => (c - b'0' + 52) as u32,
                b'+' => 62,
                b'/' => 63,
                _ => 0,
            };
        }
        let n = (v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3];
        r.push((n >> 16) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' {
            r.push((n >> 8) as u8);
        }
        if chunk.len() > 3 && chunk[3] != b'=' {
            r.push(n as u8);
        }
    }
    r
}

// --- MacKeyStore ---

#[derive(Clone)]
pub struct MacKeyStore {
    base_dir: PathBuf,
}

impl Default for MacKeyStore {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self {
            base_dir: PathBuf::from(home).join("Library").join("Application Support").join("secret-manager").join("keys"),
        }
    }
}

impl MacKeyStore {
    pub fn new() -> Self { Self::default() }
    fn path_for(&self, name: &str) -> PathBuf { self.base_dir.join(name) }
}

impl KeyStore for MacKeyStore {
    fn store(&self, name: &str, data: &[u8]) -> Result<()> {
        let path = self.path_for(name);
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, data)?;
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

// --- MacSecureInput ---

#[derive(Clone)]
pub struct MacSecureInput;

impl Default for MacSecureInput {
    fn default() -> Self { Self }
}

impl SecureInput for MacSecureInput {
    fn prompt_password(&self, prompt: &str) -> Result<String> {
        use std::io::{Read, Write};
        let mut tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")
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

// --- MacClipboard ---

#[derive(Clone)]
pub struct MacClipboard;

impl Default for MacClipboard {
    fn default() -> Self { Self }
}

impl SystemClipboard for MacClipboard {
    fn copy(&self, text: &str) -> Result<()> {
        use std::io::Write;
        let mut child = Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| Error::Storage(format!("pbcopy failed: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(text.as_bytes()).ok();
        }
        let _ = child.wait();
        Ok(())
    }
    fn paste(&self) -> Result<String> {
        let output = Command::new("pbpaste")
            .output()
            .map_err(|e| Error::Storage(format!("pbpaste failed: {e}")))?;
        String::from_utf8(output.stdout)
            .map_err(|e| Error::Storage(format!("UTF-8 error: {e}")))
    }
    fn clear(&self) -> Result<()> {
        self.copy("")
    }
}

// --- MacSessionPersistence ---

#[derive(Clone)]
pub struct MacSessionPersistence {
    session_dir: PathBuf,
}

impl Default for MacSessionPersistence {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self {
            session_dir: PathBuf::from(home).join("Library").join("Application Support").join("secret-manager").join("sessions"),
        }
    }
}

impl MacSessionPersistence {
    pub fn new() -> Self { Self::default() }
    fn path_for(&self, service: &str, account: &str) -> PathBuf {
        self.session_dir.join(format!("{}_{}", service, account))
    }
}

impl SessionPersistence for MacSessionPersistence {
    fn save_token(&self, service: &str, account: &str, token: &SessionToken) -> Result<()> {
        let path = self.path_for(service, account);
        std::fs::create_dir_all(path.parent().unwrap())?;
        let now_secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let ttl = token.time_remaining().map(|d| d.as_secs()).unwrap_or(0);
        let stored = format!("{}\n{}\n{}",
            hex_encode(token.token_id()),
            now_secs + ttl,
            base64_encode(&token.wrapped_vek().to_bytes())
        );
        std::fs::write(&path, stored)?;
        Ok(())
    }

    fn load_token(&self, service: &str, account: &str) -> Result<Option<SessionToken>> {
        let path = self.path_for(service, account);
        if !path.exists() { return Ok(None); }
        let content = std::fs::read_to_string(&path).map_err(|e| Error::Storage(e.to_string()))?;
        let mut lines = content.lines();
        let token_id = hex_decode(lines.next().unwrap_or(""));
        let expires_at: u64 = lines.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let wvek_bytes = base64_decode(lines.next().unwrap_or(""));
        if token_id.len() != 16 || expires_at == 0 { return Ok(None); }
        let mut tid = [0u8; 16];
        tid.copy_from_slice(&token_id);
        if std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) > expires_at {
            let _ = std::fs::remove_file(&path);
            return Ok(None);
        }
        let wvek = WrappedVek::from_bytes(&wvek_bytes).map_err(|e| Error::Storage(e.to_string()))?;
        let token = SessionToken::new(wvek, std::time::Duration::from_secs(0));
        Ok(Some(token))
    }

    fn delete_token(&self, service: &str, account: &str) -> Result<()> {
        std::fs::remove_file(self.path_for(service, account)).ok();
        Ok(())
    }
}

// --- MacPlatform ---

pub struct MacPlatform {
    key_store: MacKeyStore,
    secure_input: MacSecureInput,
    clipboard: MacClipboard,
    session_persistence: MacSessionPersistence,
}

impl Default for MacPlatform {
    fn default() -> Self { Self::new() }
}

impl MacPlatform {
    pub fn new() -> Self {
        Self {
            key_store: MacKeyStore::default(),
            secure_input: MacSecureInput,
            clipboard: MacClipboard,
            session_persistence: MacSessionPersistence::default(),
        }
    }
}

impl Platform for MacPlatform {
    fn key_store(&self) -> Arc<dyn KeyStore> { Arc::new(self.key_store.clone()) }
    fn secure_input(&self) -> Arc<dyn SecureInput> { Arc::new(self.secure_input.clone()) }
    fn clipboard(&self) -> Arc<dyn SystemClipboard> { Arc::new(self.clipboard.clone()) }
    fn session_persistence(&self) -> Arc<dyn SessionPersistence> { Arc::new(self.session_persistence.clone()) }
}
