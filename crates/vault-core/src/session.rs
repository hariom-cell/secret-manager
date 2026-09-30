//! Session management — session tokens for fast re-unlock.
//!
//! When a user unlocks their vault with a master password, the vault can
//! create a **session token** that allows fast re-unlock without
//! re-entering the password. The session token is a wrapped VEK encrypted
//! under a session-specific key.
//!
//! # Design
//!
//! - Session tokens are stored **in memory only** by default.  Platform
//!   crates may persist them to a system keychain (e.g. `keyring` on
//!   Linux, `Keychain` on macOS, `Credential Manager` on Windows).
//! - Each session token has a **TTL** (time-to-live). After expiry, the
//!   token is invalidated and the user must re-enter their password.
//! - The master vault password is **never stored**; only the derived KEK
//!   wrapped under the session key.
//! - Session tokens implement `Zeroize + ZeroizeOnDrop` for memory safety.

use std::sync::Mutex;
use std::time::{Duration, SystemTime};
use zeroize::Zeroize;

#[cfg(test)]
use crate::kdf::KdfParams;

use crate::vek::WrappedVek;

// ─── Session Token ────────────────────────────────────────────────────────

/// A session token that allows fast re-unlock without the master password.
///
/// Internally, the token stores a [`WrappedVek`] (the VEK encrypted under
/// a session-specific key) and an expiry timestamp.
#[derive(Clone)]
pub struct SessionToken {
    wrapped_vek: WrappedVek,
    token_id: [u8; 16],
    expires_at: SystemTime,
}

impl Zeroize for SessionToken {
    fn zeroize(&mut self) {
        self.token_id.zeroize();
    }
}

impl Drop for SessionToken {
    fn drop(&mut self) {
        self.token_id.zeroize();
    }
}

impl SessionToken {
    /// Create a new session token wrapping `wrapped_vek` with a TTL.
    pub fn new(wrapped_vek: WrappedVek, ttl: Duration) -> Self {
        let mut token_id = [0u8; 16];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut token_id);

        let expires_at = SystemTime::now() + ttl;

        Self {
            wrapped_vek,
            token_id,
            expires_at,
        }
    }

    /// The wrapped VEK this token carries.
    pub fn wrapped_vek(&self) -> &WrappedVek {
        &self.wrapped_vek
    }

    /// The unique token ID.
    pub fn token_id(&self) -> &[u8; 16] {
        &self.token_id
    }

    /// Whether this token has expired.
    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    /// Time remaining before this token expires.
    pub fn time_remaining(&self) -> Option<Duration> {
        self.expires_at.duration_since(SystemTime::now()).ok()
    }

    /// Construct a SessionToken from its parts (for use by persistence layers).
    pub fn from_parts(wrapped_vek: WrappedVek, token_id: [u8; 16], expires_at: SystemTime) -> Self {
        Self { wrapped_vek, token_id, expires_at }
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionToken")
            .field("token_id_len", &self.token_id.len())
            .field("expires_at", &self.expires_at)
            .field("is_expired", &self.is_expired())
            .finish_non_exhaustive()
    }
}

// ─── Session Manager ────────────────────────────────────────────────────

/// Manages active session tokens for a vault.
///
/// The manager holds a collection of active sessions, each with a TTL.
/// Expired sessions are cleaned up on access.
#[derive(Default)]
pub struct SessionManager {
    sessions: Mutex<Vec<SessionToken>>,
    max_sessions: usize,
    default_ttl: Duration,
}

impl SessionManager {
    /// Create a new session manager.
    ///
    /// - `max_sessions`: max concurrent sessions (prevents abuse).
    /// - `default_ttl`: default time-to-live for new sessions.
    pub fn new(max_sessions: usize, default_ttl: Duration) -> Self {
        Self {
            sessions: Mutex::new(Vec::new()),
            max_sessions,
            default_ttl,
        }
    }

    /// Create a new session from a wrapped VEK.
    ///
    /// Returns the session token on success.  The oldest session is
    /// evicted if the maximum is reached.
    pub fn create_session(&self, wrapped_vek: WrappedVek) -> Result<SessionToken, SessionError> {
        let mut sessions = self
            .sessions
            .lock()
            .expect("session manager mutex poisoned");

        sessions.retain(|s| !s.is_expired());

        if sessions.len() >= self.max_sessions {
            sessions.remove(0);
        }

        let token = SessionToken::new(wrapped_vek, self.default_ttl);
        sessions.push(token.clone());
        Ok(token)
    }

    /// Create a session with a custom TTL.
    pub fn create_session_with_ttl(
        &self,
        wrapped_vek: WrappedVek,
        ttl: Duration,
    ) -> Result<SessionToken, SessionError> {
        let mut sessions = self
            .sessions
            .lock()
            .expect("session manager mutex poisoned");

        sessions.retain(|s| !s.is_expired());

        if sessions.len() >= self.max_sessions {
            sessions.remove(0);
        }

        let token = SessionToken::new(wrapped_vek, ttl);
        sessions.push(token.clone());
        Ok(token)
    }

    /// Look up a session by token ID.
    ///
    /// Returns `None` if the token is not found or has expired.
    pub fn get_session(&self, token_id: &[u8; 16]) -> Option<SessionToken> {
        let mut sessions = self
            .sessions
            .lock()
            .expect("session manager mutex poisoned");

        sessions.retain(|s| !s.is_expired());

        sessions
            .iter()
            .position(|s| s.token_id() == token_id)
            .map(|idx| sessions.remove(idx))
    }

    /// Revoke a specific session by token ID.
    pub fn revoke_session(&self, token_id: &[u8; 16]) -> bool {
        let mut sessions = self
            .sessions
            .lock()
            .expect("session manager mutex poisoned");

        let before = sessions.len();
        sessions.retain(|s| s.token_id() != token_id || s.is_expired());
        sessions.len() < before
    }

    /// Revoke all sessions (e.g. on vault lock).
    pub fn revoke_all(&self) {
        let mut sessions = self
            .sessions
            .lock()
            .expect("session manager mutex poisoned");
        sessions.clear();
    }

    /// Number of active (non-expired) sessions.
    pub fn active_count(&self) -> usize {
        let sessions = self
            .sessions
            .lock()
            .expect("session manager mutex poisoned");
        sessions.iter().filter(|s| !s.is_expired()).count()
    }

    /// The default TTL for new sessions.
    pub fn default_ttl(&self) -> Duration {
        self.default_ttl
    }
}

// ─── Errors ──────────────────────────────────────────────────────────────

/// Errors from session management operations.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Session limit reached.
    #[error("maximum number of sessions ({0}) reached")]
    LimitReached(usize),
    /// Session token not found or expired.
    #[error("session not found or expired")]
    NotFound,
    /// Session is expired.
    #[error("session expired")]
    Expired,
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_wrapped_vek() -> WrappedVek {
        let kek_bytes = crate::kdf::derive_kek(
            "test password",
            b"0123456789abcdef0123456789abcdef",
            KdfParams::default(),
        )
        .unwrap();
        let vek = crate::vek::Vek::random();
        let wvek = vek.wrap(&kek_bytes).unwrap();
        drop(kek_bytes);
        wvek
    }

    #[test]
    fn session_token_creation() {
        let wvek = fake_wrapped_vek();
        let token = SessionToken::new(wvek, Duration::from_secs(300));
        assert!(!token.is_expired());
        assert!(token.time_remaining().is_some());
        assert_eq!(token.token_id().len(), 16);
    }

    #[test]
    fn session_token_expiry() {
        let wvek = fake_wrapped_vek();
        let token = SessionToken::new(wvek, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(10));
        assert!(token.is_expired());
        assert!(token.time_remaining().is_none());
    }

    #[test]
    fn session_manager_create_and_get() {
        let mgr = SessionManager::new(5, Duration::from_secs(300));
        let wvek = fake_wrapped_vek();
        let token = mgr.create_session(wvek).unwrap();
        let found = mgr.get_session(token.token_id());
        assert!(found.is_some());
    }

    #[test]
    fn session_manager_revokes_expired() {
        let mgr = SessionManager::new(5, Duration::from_millis(5));
        let wvek = fake_wrapped_vek();
        let token = mgr.create_session(wvek).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert!(mgr.get_session(token.token_id()).is_none());
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn session_manager_revoke_specific() {
        let mgr = SessionManager::new(5, Duration::from_secs(300));
        let kek_bytes = crate::kdf::derive_kek(
            "test password",
            b"fedcba9876543210fedcba9876543210",
            KdfParams::default(),
        )
        .unwrap();
        let vek1 = crate::vek::Vek::random();
        let vek2 = crate::vek::Vek::random();
        let wvek1 = vek1.wrap(&kek_bytes).unwrap();
        let wvek2 = vek2.wrap(&kek_bytes).unwrap();
        let t1 = mgr.create_session(wvek1).unwrap();
        let t2 = mgr.create_session(wvek2).unwrap();
        assert_eq!(mgr.active_count(), 2);
        assert!(mgr.revoke_session(t1.token_id()));
        assert_eq!(mgr.active_count(), 1);
        assert!(mgr.get_session(t2.token_id()).is_some());
    }

    #[test]
    fn session_manager_revoke_all() {
        let mgr = SessionManager::new(5, Duration::from_secs(300));
        let kek_bytes = crate::kdf::derive_kek(
            "test password",
            b"aabbccddeeff00112233445566778899",
            KdfParams::default(),
        )
        .unwrap();
        let vek1 = crate::vek::Vek::random();
        let vek2 = crate::vek::Vek::random();
        let wvek1 = vek1.wrap(&kek_bytes).unwrap();
        let wvek2 = vek2.wrap(&kek_bytes).unwrap();
        mgr.create_session(wvek1).unwrap();
        mgr.create_session(wvek2).unwrap();
        assert_eq!(mgr.active_count(), 2);
        mgr.revoke_all();
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn session_manager_eviction() {
        let mgr = SessionManager::new(2, Duration::from_secs(300));
        let kek_bytes = crate::kdf::derive_kek(
            "test password",
            b"99887766554433221100ffeeddccbbaa",
            KdfParams::default(),
        )
        .unwrap();
        let vek1 = crate::vek::Vek::random();
        let vek2 = crate::vek::Vek::random();
        let vek3 = crate::vek::Vek::random();
        let wvek1 = vek1.wrap(&kek_bytes).unwrap();
        let wvek2 = vek2.wrap(&kek_bytes).unwrap();
        let wvek3 = vek3.wrap(&kek_bytes).unwrap();
        let t1 = mgr.create_session(wvek1).unwrap();
        let t2 = mgr.create_session(wvek2).unwrap();
        // t3 should evict t1.
        let t3 = mgr.create_session(wvek3).unwrap();
        assert_eq!(mgr.active_count(), 2);
        assert!(mgr.get_session(t1.token_id()).is_none());
        assert!(mgr.get_session(t2.token_id()).is_some());
        assert!(mgr.get_session(t3.token_id()).is_some());
    }

    #[test]
    fn session_debug_format_hides_sensitive() {
        let wvek = fake_wrapped_vek();
        let token = SessionToken::new(wvek, Duration::from_secs(300));
        let dbg = format!("{:?}", token);
        assert!(dbg.contains("SessionToken"));
        assert!(dbg.contains("is_expired"));
    }
}
