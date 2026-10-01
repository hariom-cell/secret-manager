//! Android platform crate for the Secret Manager vault.

use std::path::PathBuf;
use std::sync::Arc;

use vault_core::ffi::{KeyStore, Platform, SecureInput, SessionPersistence, SystemClipboard};
use vault_core::session::SessionToken;
use vault_core::vek::WrappedVek;
use vault_core::{Error, Result};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AndroidError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("UTF-8 error: {0}")]
    Utf8(#[from] std::string::FromUtf8Error),
}

impl From<AndroidError> for Error {
    fn from(e: AndroidError) -> Self {
        match e {
            AndroidError::Io(e) => Error::Storage(e.to_string()),
            AndroidError::Utf8(e) => Error::Storage(e.to_string()),
        }
    }
}

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
    const C: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut r = String::new();
    for chunk in data.chunks(3) {
        let mut b = [0u8; 3]; b[..chunk.len()].copy_from_slice(chunk);
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        r.push(C[((n >> 18) & 0x3F) as usize] as char);
        r.push(C[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 { r.push(C[((n >> 6) & 0x3F) as usize] as char); } else { r.push('='); }
        if chunk.len() > 2 { r.push(C[(n & 0x3F) as usize] as char); } else { r.push('='); }
    }
    r
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
                b'+' => 62, b'/' => 63, _ => 0,
            };
        }
        let n = (v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3];
        r.push((n >> 16) as u8);
        if chunk.len() > 2 && chunk[2] != b'=' { r.push((n >> 8) as u8); }
        if chunk.len() > 3 && chunk[3] != b'=' { r.push(n as u8); }
    }
    r
}

#[derive(Clone)]
pub struct AndroidKeyStore {
    base_dir: PathBuf,
}

impl Default for AndroidKeyStore {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self { base_dir: PathBuf::from(home).join(".android").join("vault").join("keystore") }
    }
}

impl AndroidKeyStore { pub fn new() -> Self { Self::default() } }

impl KeyStore for AndroidKeyStore {
    fn store(&self, name: &str, data: &[u8]) -> Result<()> {
        let path = self.base_dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(&path, data)?;
        Ok(())
    }
    fn retrieve(&self, name: &str) -> Result<Vec<u8>> {
        std::fs::read(self.base_dir.join(name)).map_err(|e| Error::Storage(e.to_string()))
    }
    fn delete(&self, name: &str) -> Result<()> {
        std::fs::remove_file(self.base_dir.join(name)).map_err(|e| Error::Storage(e.to_string()))
    }
    fn contains(&self, name: &str) -> bool { self.base_dir.join(name).exists() }
}

#[derive(Clone)]
pub struct AndroidSecureInput;
impl Default for AndroidSecureInput { fn default() -> Self { Self } }
impl SecureInput for AndroidSecureInput {
    fn prompt_password(&self, _p: &str) -> Result<String> {
        Err(Error::Storage("requires JNI".into()))
    }
    fn confirm_password(&self, _p: &str, _e: &str) -> Result<bool> {
        Err(Error::Storage("requires JNI".into()))
    }
}

#[derive(Clone)]
pub struct AndroidClipboard;
impl Default for AndroidClipboard { fn default() -> Self { Self } }
impl SystemClipboard for AndroidClipboard {
    fn copy(&self, _t: &str) -> Result<()> { Ok(()) }
    fn paste(&self) -> Result<String> { Err(Error::Storage("requires JNI".into())) }
    fn clear(&self) -> Result<()> { Ok(()) }
}

#[derive(Clone)]
pub struct AndroidSessionPersistence {
    session_dir: PathBuf,
}

impl Default for AndroidSessionPersistence {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self { session_dir: PathBuf::from(home).join(".android").join("vault").join("sessions") }
    }
}

impl AndroidSessionPersistence { pub fn new() -> Self { Self::default() } }

impl SessionPersistence for AndroidSessionPersistence {
    fn save_token(&self, service: &str, account: &str, token: &SessionToken) -> Result<()> {
        let path = self.session_dir.join(format!("{}_{}", service, account));
        std::fs::create_dir_all(path.parent().unwrap())?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let stored = format!("{}\n{}\n{}",
            hex_encode(token.token_id()),
            now + token.time_remaining().map(|d| d.as_secs()).unwrap_or(0),
            base64_encode(&token.wrapped_vek().to_bytes())
        );
        std::fs::write(&path, stored)?;
        Ok(())
    }
    fn load_token(&self, service: &str, account: &str) -> Result<Option<SessionToken>> {
        let path = self.session_dir.join(format!("{}_{}", service, account));
        if !path.exists() { return Ok(None); }
        let content = std::fs::read_to_string(&path).map_err(|e| Error::Storage(e.to_string()))?;
        let mut lines = content.lines();
        let tid = hex_decode(lines.next().unwrap_or(""));
        let exp: u64 = lines.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let wb = base64_decode(lines.next().unwrap_or(""));
        if tid.len() != 16 || exp == 0 { return Ok(None); }
        let mut id = [0u8; 16]; id.copy_from_slice(&tid);
        if std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) > exp {
            let _ = std::fs::remove_file(&path); return Ok(None);
        }
        let wvek = WrappedVek::from_bytes(&wb).map_err(|e| Error::Storage(e.to_string()))?;
        Ok(Some(SessionToken::new(wvek, std::time::Duration::from_secs(0))))
    }
    fn delete_token(&self, service: &str, account: &str) -> Result<()> {
        std::fs::remove_file(self.session_dir.join(format!("{}_{}", service, account))).ok();
        Ok(())
    }
}

pub struct AndroidPlatform {
    key_store: AndroidKeyStore,
    secure_input: AndroidSecureInput,
    clipboard: AndroidClipboard,
    session_persistence: AndroidSessionPersistence,
}

impl Default for AndroidPlatform { fn default() -> Self { Self::new() } }
impl AndroidPlatform {
    pub fn new() -> Self {
        Self {
            key_store: AndroidKeyStore::default(),
            secure_input: AndroidSecureInput,
            clipboard: AndroidClipboard,
            session_persistence: AndroidSessionPersistence::default(),
        }
    }
}

impl Platform for AndroidPlatform {
    fn key_store(&self) -> Arc<dyn KeyStore> { Arc::new(self.key_store.clone()) }
    fn secure_input(&self) -> Arc<dyn SecureInput> { Arc::new(self.secure_input.clone()) }
    fn clipboard(&self) -> Arc<dyn SystemClipboard> { Arc::new(self.clipboard.clone()) }
    fn session_persistence(&self) -> Arc<dyn SessionPersistence> { Arc::new(self.session_persistence.clone()) }
}
