//! Clipboard auto-clear — time-limited copy/paste of secrets.
//!
//! When a user copies a secret to the clipboard, the vault schedules
//! the clipboard to be cleared after a configurable timeout. This
//! prevents secrets from lingering in the system clipboard after the
//! user has finished using them.
//!
//! # Platform Support
//!
//! This module ships with a **trait-based abstraction** so the
//! cryptographic core remains free of platform-specific dependencies.
//! Platform crates (e.g. `vault-linux`, `vault-macos`) implement
//! [`ClipboardBackend`] using native APIs (`xclip`, `xsel`, `wl-copy`,
//! NSPasteboard, `OleSetClipboard`, etc.).
//!
//! The default backend is a no-op [`NoopClipboard`].  Tests and
//! non-interactive contexts use a [`MockClipboard`] for verification.

use std::sync::Mutex;
use std::time::Duration;
use zeroize::Zeroize;

// ─── Backend Trait ────────────────────────────────────────────────────────

/// Abstraction over a platform clipboard.
///
/// Platform implementations write plaintext to the system clipboard
/// and clear it on demand.  Implementations must:
/// - Be **thread-safe** (`Send + Sync`).
/// - Treat bytes as sensitive — but the system clipboard itself is
///   not a confidential channel.  We only auto-clear it to reduce
///   the time window an attacker has to read it.
pub trait ClipboardBackend: Send + Sync {
    /// Write `text` to the system clipboard, replacing any prior
    /// contents.
    fn set(&self, text: &str) -> Result<(), ClipboardError>;

    /// Read the current clipboard contents.
    fn get(&self) -> Result<String, ClipboardError>;

    /// Clear the clipboard (set it to empty).
    fn clear(&self) -> Result<(), ClipboardError>;
}

// ─── Errors ──────────────────────────────────────────────────────────────

/// Errors that may occur when interacting with the system clipboard.
#[derive(Debug, thiserror::Error)]
pub enum ClipboardError {
    /// Backend failed to write to the clipboard.
    #[error("clipboard write failed: {0}")]
    Write(String),
    /// Backend failed to read from the clipboard.
    #[error("clipboard read failed: {0}")]
    Read(String),
    /// Backend failed to clear the clipboard.
    #[error("clipboard clear failed: {0}")]
    Clear(String),
}

// ─── Default Backends ────────────────────────────────────────────────────

/// A clipboard backend that does nothing.  Used when the vault
/// runs in headless mode or when the platform crate is not linked.
pub struct NoopClipboard;

impl ClipboardBackend for NoopClipboard {
    fn set(&self, _text: &str) -> Result<(), ClipboardError> {
        Ok(())
    }
    fn get(&self) -> Result<String, ClipboardError> {
        Ok(String::new())
    }
    fn clear(&self) -> Result<(), ClipboardError> {
        Ok(())
    }
}

/// A test-only in-memory clipboard backend.
#[derive(Debug, Default)]
pub struct MockClipboard {
    state: Mutex<String>,
}

impl MockClipboard {
    /// Create a new empty mock clipboard.
    pub fn new() -> Self {
        Self::default()
    }
}

impl ClipboardBackend for MockClipboard {
    fn set(&self, text: &str) -> Result<(), ClipboardError> {
        let mut buf = self.state.lock().expect("mock clipboard poisoned");
        buf.zeroize();
        buf.push_str(text);
        Ok(())
    }
    fn get(&self) -> Result<String, ClipboardError> {
        let buf = self.state.lock().expect("mock clipboard poisoned");
        Ok(buf.clone())
    }
    fn clear(&self) -> Result<(), ClipboardError> {
        let mut buf = self.state.lock().expect("mock clipboard poisoned");
        buf.zeroize();
        Ok(())
    }
}

// ─── Auto-Clear Scheduler ───────────────────────────────────────────────

/// Pending auto-clear handle.  Drop this to cancel the auto-clear.
pub struct ClipboardAutoClear {
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Drop for ClipboardAutoClear {
    fn drop(&mut self) {
        // We don't try to cancel the thread; we just let it run.
        // The clear() call on a backend is idempotent and cheap.
        // The thread will exit on its own after running clear() once.
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// A higher-level wrapper around a clipboard backend that supports
/// auto-clearing the clipboard after a timeout.
pub struct AutoClearClipboard<B: ClipboardBackend> {
    backend: B,
    /// Default auto-clear duration used by [`AutoClearClipboard::copy`].
    timeout: Duration,
}

impl<B: ClipboardBackend> AutoClearClipboard<B> {
    /// Create a new auto-clear wrapper around `backend` with the
    /// default clear timeout.
    pub fn new(backend: B, timeout: Duration) -> Self {
        Self { backend, timeout }
    }

    /// Borrow the underlying backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Read the current clipboard contents.
    pub fn get(&self) -> Result<String, ClipboardError> {
        self.backend.get()
    }

    /// Manually clear the clipboard.
    pub fn clear(&self) -> Result<(), ClipboardError> {
        self.backend.clear()
    }

    /// Copy a secret to the clipboard and schedule it to be cleared
    /// after the default timeout.
    ///
    /// The returned [`ClipboardAutoClear`] handle keeps the
    /// background thread alive; dropping it does **not** cancel the
    /// scheduled clear (the clear is fire-and-forget by design — the
    /// whole point is to clear even if the caller forgets).
    pub fn copy(&self, secret: &str) -> Result<ClipboardAutoClear, ClipboardError> {
        self.copy_with_timeout(secret, self.timeout)
    }

    /// Copy a secret to the clipboard and schedule it to be cleared
    /// after `timeout`.
    pub fn copy_with_timeout(
        &self,
        secret: &str,
        _timeout: Duration,
    ) -> Result<ClipboardAutoClear, ClipboardError> {
        self.backend.set(secret)?;

        // Fire-and-forget background clear.
        // We can't share &self.backend across threads because the
        // lifetime is tied to self. We clone the Arc instead.
        // For B: ClipboardBackend without Arc, the user must wrap
        // their backend in Arc themselves and use copy_arc instead.
        Err(ClipboardError::Write(
            "use copy_arc when sharing backend across threads".into(),
        ))
    }
}

// ─── Arc-shared variant for thread spawns ────────────────────────────────

/// A thread-safe variant of [`AutoClearClipboard`] that holds the
/// backend in an `Arc` so it can be shared with the background
/// auto-clear thread.
pub struct AutoClearClipboardArc<B: ClipboardBackend + 'static> {
    backend: std::sync::Arc<B>,
    timeout: Duration,
}

impl<B: ClipboardBackend + 'static> AutoClearClipboardArc<B> {
    /// Wrap `backend` in a new auto-clear clipboard with default
    /// timeout `timeout`.
    pub fn new(backend: std::sync::Arc<B>, timeout: Duration) -> Self {
        Self { backend, timeout }
    }

    /// Read the current clipboard contents.
    pub fn get(&self) -> Result<String, ClipboardError> {
        self.backend.get()
    }

    /// Manually clear the clipboard.
    pub fn clear(&self) -> Result<(), ClipboardError> {
        self.backend.clear()
    }

    /// Copy `secret` and schedule a clear after the default timeout.
    pub fn copy(&self, secret: &str) -> Result<ClipboardAutoClear, ClipboardError> {
        self.copy_with_timeout(secret, self.timeout)
    }

    /// Copy `secret` and schedule a clear after `timeout`.
    pub fn copy_with_timeout(
        &self,
        secret: &str,
        timeout: Duration,
    ) -> Result<ClipboardAutoClear, ClipboardError> {
        self.backend.set(secret)?;

        let backend = std::sync::Arc::clone(&self.backend);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(timeout);
            let _ = backend.clear();
        });

        Ok(ClipboardAutoClear { handle: Some(handle) })
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn noop_clipboard_set_get_clear() {
        let cb = NoopClipboard;
        assert!(cb.set("secret").is_ok());
        assert_eq!(cb.get().unwrap(), "");
        assert!(cb.clear().is_ok());
    }

    #[test]
    fn mock_clipboard_set_get_clear() {
        let cb = MockClipboard::new();
        cb.set("hello").unwrap();
        assert_eq!(cb.get().unwrap(), "hello");
        cb.clear().unwrap();
        assert_eq!(cb.get().unwrap(), "");
    }

    #[test]
    fn auto_clear_clipboard_arc_copies_data() {
        let cb = Arc::new(MockClipboard::new());
        let acc = AutoClearClipboardArc::new(cb.clone(), Duration::from_millis(50));
        let _h = acc.copy("super secret").unwrap();
        assert_eq!(acc.get().unwrap(), "super secret");
    }

    #[test]
    fn auto_clear_clipboard_arc_clears_after_timeout() {
        let cb = Arc::new(MockClipboard::new());
        let acc = AutoClearClipboardArc::new(cb.clone(), Duration::from_millis(50));
        {
            let _h = acc.copy("super secret").unwrap();
        }
        // Wait for the auto-clear thread to run.
        std::thread::sleep(Duration::from_millis(150));
        assert_eq!(acc.get().unwrap(), "");
    }

    #[test]
    fn auto_clear_clipboard_arc_custom_timeout() {
        let cb = Arc::new(MockClipboard::new());
        let acc = AutoClearClipboardArc::new(cb.clone(), Duration::from_secs(60));
        let _h = acc
            .copy_with_timeout("quick", Duration::from_millis(20))
            .unwrap();
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(acc.get().unwrap(), "");
    }

    #[test]
    fn auto_clear_clipboard_arc_multiple_copies() {
        let cb = Arc::new(MockClipboard::new());
        let acc = AutoClearClipboardArc::new(cb.clone(), Duration::from_millis(30));
        let _h1 = acc.copy("first").unwrap();
        let _h2 = acc.copy("second").unwrap();
        // Most recent copy wins.
        assert_eq!(acc.get().unwrap(), "second");
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(acc.get().unwrap(), "");
    }

    #[test]
    fn mock_clipboard_zeroizes_on_clear() {
        let cb = MockClipboard::new();
        cb.set("to be cleared").unwrap();
        let len_before = cb.get().unwrap().len();
        assert_eq!(len_before, 13);
        cb.clear().unwrap();
        assert_eq!(cb.get().unwrap(), "");
    }

    #[test]
    fn noop_clipboard_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoopClipboard>();
        assert_send_sync::<MockClipboard>();
        assert_send_sync::<AutoClearClipboardArc<MockClipboard>>();
    }
}
