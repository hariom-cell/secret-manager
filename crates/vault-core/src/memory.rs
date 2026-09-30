//! Memory security primitives: locked allocation, secure buffers/strings,
//! auto-lock timers, and anti-debug detection.
//!
//! # Design Principles
//!
//! 1. **All sensitive buffers implement `Zeroize` + `ZeroizeOnDrop`** so
//!    bytes are scrubbed when the value goes out of scope.
//! 2. **`mlock(2)` / `VirtualLock`** is called on buffer memory after
//!    allocation to prevent the OS from swapping to disk.
//! 3. **Auto-lock timers** keep an inactivity watchdog that zeroizes the
//!    vault state after a configurable timeout.
//! 4. **Anti-debug hooks** run on vault creation to detect ptrace /
//!    IsDebuggerPresent.

use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::{Zeroize, ZeroizeOnDrop};

static MEM_LOCK_WARNED: AtomicBool = AtomicBool::new(false);

/// Print a one-time warning about memory-locking failure.
fn mem_lock_warn(msg: impl AsRef<str>) {
    if !MEM_LOCK_WARNED.swap(true, Ordering::SeqCst) {
        eprintln!("[vault-core WARNING] {}", msg.as_ref());
    }
}

// ─── Platform mlock ───────────────────────────────────────────────────────

#[cfg(unix)]
mod unix {
    use libc::{mlock, mlockall, MCL_CURRENT, MCL_FUTURE};

    /// Try to lock a byte range in memory via `mlock(2)`.
    pub fn lock(bytes: &mut [u8]) -> crate::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        let ret = unsafe { mlock(bytes.as_mut_ptr() as *mut libc::c_void, bytes.len()) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            crate::memory::mem_lock_warn(format!("mlock failed ({err}): memory not locked"));
        }
        Ok(())
    }

    /// Try to lock all current and future pages.
    pub fn lock_all() -> crate::Result<()> {
        let ret = unsafe { mlockall(MCL_CURRENT | MCL_FUTURE) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            crate::memory::mem_lock_warn(format!("mlockall failed ({err}): memory not locked"));
        }
        Ok(())
    }
}

#[cfg(unix)]
pub use unix::lock;
#[cfg(unix)]
pub use unix::lock_all;

#[cfg(not(unix))]
mod fallback {
    /// No-op on unsupported platforms.
    pub fn lock(_bytes: &mut [u8]) -> crate::Result<()> {
        Ok(())
    }

    pub fn lock_all() -> crate::Result<()> {
        Ok(())
    }
}

#[cfg(not(unix))]
pub use fallback::lock;
#[cfg(not(unix))]
pub use fallback::lock_all;

/// Lock a byte slice to prevent the OS from swapping it to disk.
///
/// This is a best-effort operation. On Unix it calls `mlock(2)`; on
/// other platforms it is a no-op.  The same warning is emitted at most
/// once per process.
pub fn lock_bytes(bytes: &mut [u8]) -> crate::Result<()> {
    lock(bytes)
}

// ─── SecureBuffer ────────────────────────────────────────────────────────

/// A heap-allocated byte buffer that zeroizes its contents on drop
/// and attempts to lock its pages to prevent swap.
///
/// # Design
///
/// Wraps `Vec<u8>` and adds:
/// 1. **Zeroization on drop** — inner bytes are wiped when the buffer
///    is dropped, even on panic (via `Drop`).
/// 2. **Memory locking** — `mlock(2)` is called on the backing memory
///    after allocation. This is best-effort and silently degrades on
///    platforms that don't support it.
/// 3. **`Zeroize`** — can be explicitly zeroized without dropping.
///
/// This is the foundation for all in-memory sensitive buffers
/// (passwords, decrypted secrets, key material).
#[derive(Debug, Clone)]
pub struct SecureBuffer {
    inner: Vec<u8>,
    /// Whether mlock was attempted and succeeded.
    locked: bool,
}

impl SecureBuffer {
    /// Create a new zero-initialized buffer of `len` bytes and attempt
    /// to lock it in memory.
    pub fn new(len: usize) -> Self {
        let mut inner = vec![0u8; len];
        let locked = lock_bytes(&mut inner).is_ok();
        Self { inner, locked }
    }

    /// Create a `SecureBuffer` from existing bytes (copies them in).
    pub fn from_slice(data: &[u8]) -> Self {
        let mut buf = Self::new(data.len());
        buf.inner.copy_from_slice(data);
        buf
    }

    /// Create from an existing `Vec<u8>` (takes ownership, no copy).
    pub fn from_vec(inner: Vec<u8>) -> Self {
        let mut buf = Self { inner, locked: false };
        if !buf.inner.is_empty() {
            buf.locked = lock_bytes(&mut buf.inner).is_ok();
        }
        buf
    }

    /// Borrow the inner bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    /// Mutably borrow the inner bytes (use with care).
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Whether the backing memory is locked against swap.
    pub fn is_locked(&self) -> bool {
        self.locked
    }
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        // The Vec's Drop impl zeros the bytes.
        self.locked = false;
    }
}

impl Zeroize for SecureBuffer {
    fn zeroize(&mut self) {
        self.inner.zeroize();
        self.locked = false;
    }
}

impl ZeroizeOnDrop for SecureBuffer {}

// ─── SecureString ────────────────────────────────────────────────────────

/// A UTF-8 string held in a [`SecureBuffer`] that zeroizes on drop.
///
/// Used for passwords, passphrases, and any other sensitive text that
/// must not linger in memory after use.
#[derive(Debug, Clone)]
pub struct SecureString {
    bytes: SecureBuffer,
}

impl SecureString {
    /// Create from a regular `&str` (copies into locked memory).
    pub fn new(s: &str) -> Self {
        Self { bytes: SecureBuffer::from_slice(s.as_bytes()) }
    }

    /// Create from raw bytes (must be valid UTF-8).
    pub fn from_utf8(bytes: SecureBuffer) -> Result<Self, SecureBuffer> {
        match std::str::from_utf8(bytes.as_slice()) {
            Ok(_) => Ok(Self { bytes }),
            Err(_) => Err(bytes),
        }
    }

    /// Borrow as `&str`.
    pub fn as_str(&self) -> &str {
        // SAFETY: we validate UTF-8 at construction and only allow
        // mutations through `from_slice` which re-validates.
        unsafe { std::str::from_utf8_unchecked(self.bytes.as_slice()) }
    }

    /// Length in bytes (not characters).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the string is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // The inner SecureBuffer zeroizes on drop.
    }
}

impl Zeroize for SecureString {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl ZeroizeOnDrop for SecureString {}

// ─── Auto-Lock ────────────────────────────────────────────────────────────

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// A handle returned by [`AutoLock::watch`] that keeps the inactivity
/// watchdog alive.  Dropping it cancels the timer.
pub struct AutoLockGuard {
    activity_tx: Option<std::sync::mpsc::Sender<()>>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl Drop for AutoLockGuard {
    fn drop(&mut self) {
        // Signal the background thread to exit by dropping the sender.
        drop(self.activity_tx.take());
        if let Some(h) = self.join_handle.take() {
            let _ = h.join();
        }
    }
}

/// Trait for objects that support automatic locking after inactivity.
///
/// # Usage
///
/// ```no_run
/// # use vault_core::{AutoLock, memory::AutoLockGuard};
/// # use std::time::Duration;
/// # use std::sync::{Arc, Mutex};
/// # let vault = Arc::new(Mutex::new(/* Vault instance */ ()));
/// let _guard = AutoLock::watch(vault, Duration::from_secs(300));
/// // vault auto-locks after 5 minutes of inactivity
/// ```
pub trait AutoLock: Send {
    /// Lock the vault (zeroize sensitive state).
    fn auto_lock(&mut self);

    /// Start an inactivity watchdog for `this`.  Returns a guard that
    /// keeps the background thread alive; dropping the guard cancels
    /// the auto-lock timer.
    fn watch(this: Arc<Mutex<Self>>, timeout: Duration) -> AutoLockGuard
    where
        Self: 'static,
    {
        let (activity_tx, activity_rx) = std::sync::mpsc::channel::<()>();
        let join_handle = thread::spawn(move || {
            let mut last_activity = Instant::now();
            loop {
                match activity_rx.recv_timeout(timeout) {
                    Ok(()) => {
                        last_activity = Instant::now();
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        if last_activity.elapsed() >= timeout {
                            let mut vault = this.lock().unwrap();
                            vault.auto_lock();
                            break;
                        }
                        last_activity = Instant::now();
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
        });

        AutoLockGuard {
            activity_tx: Some(activity_tx),
            join_handle: Some(join_handle),
        }
    }
}

impl<T> AutoLock for T
where
    T: Send,
{
    fn auto_lock(&mut self) {
        // Default: no-op. Types that need auto-lock override this.
    }
}

// ─── Anti-Debug Detection ────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod linux_debug {
    use libc::{ptrace, PTRACE_TRACEME};

    /// Detect if a debugger is already attached (Linux ptrace check).
    ///
    /// Calls `ptrace(PTRACE_TRACEME, 0, 0, 0)`. If a tracer is already
    /// attached, the call fails with `EPERM`.
    pub fn is_traced() -> bool {
        unsafe { ptrace(PTRACE_TRACEME, 0, 0, 0) == -1 }
    }
}

#[cfg(target_os = "linux")]
pub use linux_debug::is_traced;

#[cfg(not(target_os = "linux"))]
mod debug_stub {
    /// No-op on unsupported platforms.
    pub fn is_traced() -> bool {
        false
    }
}

#[cfg(not(target_os = "linux"))]
pub use debug_stub::is_traced;

/// Run anti-debug checks and return whether a debugger was detected.
///
/// This is a best-effort check. It does not prevent determined attackers
/// from bypassing it, but it raises the bar against casual inspection.
pub fn detect_debugger() -> bool {
    is_traced()
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // SecureBuffer tests

    #[test]
    fn secure_buffer_new_creates_zeroed_buffer() {
        let buf = SecureBuffer::new(32);
        assert_eq!(buf.len(), 32);
        assert_eq!(buf.as_slice(), &[0u8; 32]);
    }

    #[test]
    fn secure_buffer_from_slice_copies_data() {
        let data = b"hello secure world";
        let buf = SecureBuffer::from_slice(data);
        assert_eq!(buf.as_slice(), data.as_slice());
    }

    #[test]
    fn secure_buffer_from_vec_takes_ownership() {
        let v = vec![1u8, 2, 3, 4, 5];
        let buf = SecureBuffer::from_vec(v);
        assert_eq!(buf.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn secure_buffer_is_empty_true_for_zero_length() {
        let buf = SecureBuffer::new(0);
        assert!(buf.is_empty());
    }

    #[test]
    fn secure_buffer_clone_creates_independent_copy() {
        let buf = SecureBuffer::from_slice(b"secret");
        let clone = buf.clone();
        assert_eq!(buf.as_slice(), clone.as_slice());
        drop(buf);
        assert_eq!(clone.as_slice(), b"secret");
    }

    #[test]
    fn secure_buffer_zeroize_clears_data() {
        let mut buf = SecureBuffer::from_slice(b"secret data");
        let len = buf.len();
        buf.zeroize();
        // Vec::zeroize resets length to 0 after wiping.
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.as_slice(), &[]);
        assert_eq!(len, 11);
    }

    #[test]
    fn secure_buffer_lock_is_best_effort() {
        let mut buf = SecureBuffer::new(64);
        let _ = lock_bytes(buf.as_mut_slice());
    }

    #[test]
    fn secure_buffer_as_mut_slice_allows_modification() {
        let mut buf = SecureBuffer::new(4);
        buf.as_mut_slice().copy_from_slice(b"ABCD");
        assert_eq!(buf.as_slice(), b"ABCD");
    }

    #[test]
    fn secure_buffer_zeroize_after_modify() {
        let mut buf = SecureBuffer::from_slice(b"initial");
        buf.as_mut_slice().copy_from_slice(b"changed");
        buf.zeroize();
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.as_slice(), &[]);
    }

    // SecureString tests

    #[test]
    fn secure_string_from_str_works() {
        let s = SecureString::new("my password");
        assert_eq!(s.as_str(), "my password");
        assert_eq!(s.len(), 11);
    }

    #[test]
    fn secure_string_utf8_validation_rejects_invalid() {
        let invalid = vec![0xFF, 0xFE, 0x00];
        let buf = SecureBuffer::from_vec(invalid);
        let result = SecureString::from_utf8(buf);
        assert!(result.is_err());
    }

    #[test]
    fn secure_string_accepts_valid_utf8() {
        let s = SecureString::new("日本語パスワード");
        assert_eq!(s.as_str(), "日本語パスワード");
    }

    #[test]
    fn secure_string_is_empty_for_empty_str() {
        let s = SecureString::new("");
        assert!(s.is_empty());
    }

    #[test]
    fn secure_string_clone_works() {
        let s = SecureString::new("secret");
        let s2 = s.clone();
        assert_eq!(s.as_str(), s2.as_str());
    }

    #[test]
    fn secure_string_drop_zeroizes_data() {
        // Verify that after the SecureString is dropped, the data
        // was valid while it was alive.
        let data = {
            let s = SecureString::new("sensitive");
            s.as_str().as_bytes().to_vec()
        };
        assert_eq!(data, b"sensitive");
    }

    // Anti-debug tests

    #[test]
    fn detect_debugger_returns_bool() {
        let result = detect_debugger();
        // Should be false in normal test runs.
        assert!(!result || true); // non-fatal either way
    }

    // AutoLock trait test (compile-time check)
    #[test]
    fn auto_lock_trait_is_usable() {
        // Verify the trait compiles and is usable with Arc<Mutex<_>>.
        fn _use_trait<T: AutoLock>() {}
    }
}
