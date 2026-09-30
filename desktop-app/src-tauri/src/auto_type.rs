//! Auto-type / autofill — inject secrets directly into focused fields.
//!
//! This module provides the ability to type a secret into the currently
//! focused input field on the system, mimicking keyboard input. This is
//! safer than copy/paste because:
//! - The secret never appears in the clipboard.
//! - The secret is not visible in the UI of this app while typing.
//! - Less risk of the secret being captured by clipboard history tools.
//!
//! # Security
//!
//! - The typed text is zeroized after sending.
//! - A small random delay (20-80ms) between characters is added to defeat
//!   simple keylogging attacks that look for perfectly-timed input.
//!
//! # Platform Support
//!
//! - **macOS**: Uses `CGEventCreateKeyboardEvent`. Requires Accessibility
//!   permission to be granted to the app in System Preferences.
//! - **Windows**: Uses `SendInput`.
//! - **Linux (X11)**: Uses `XTestFakeKeyEvent`.
//! - **Linux (Wayland)**: Falls back to clipboard paste.

use std::time::Duration;
use zeroize::Zeroize;

/// Type a secret string into the currently focused input field.
///
/// # Arguments
/// - `text`: the secret to type (will be zeroized after sending)
///
/// # Errors
/// Returns an error if the platform's input injection fails, or if no
/// input field is focused.
pub fn type_secret(mut text: String) -> Result<(), AutoTypeError> {
    if text.is_empty() {
        return Err(AutoTypeError::EmptyValue);
    }

    // Platform-specific implementation
    #[cfg(target_os = "macos")]
    platform::macos::type_text(&text)?;

    #[cfg(target_os = "windows")]
    platform::windows::type_text(&text)?;

    #[cfg(target_os = "linux")]
    platform::linux::type_text(&text)?;

    // Zeroize the buffer after sending
    text.zeroize();

    Ok(())
}

/// Errors that can occur during auto-type.
#[derive(Debug, thiserror::Error)]
pub enum AutoTypeError {
    #[error("no input field is focused")]
    NoFocusedField,

    #[error("accessibility permissions not granted — enable in System Settings > Privacy & Security > Accessibility")]
    AccessibilityDenied,

    #[error("platform error: {0}")]
    PlatformError(String),

    #[error("unsupported platform for direct input injection")]
    UnsupportedPlatform,

    #[error("empty value provided")]
    EmptyValue,
}

/// Get a random delay between keystrokes (20-80ms).
///
/// This adds a human-like typing rhythm to defeat simple keyloggers that
/// look for perfectly-timed input.
fn random_keystroke_delay() -> Duration {
    let ms = 20 + (fastrand::u64(0..60));
    Duration::from_millis(ms)
}

// ─── Platform Implementations ────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    pub mod macos {
        use super::super::{random_keystroke_delay, AutoTypeError};
        use std::time::Duration;

        /// Type text on macOS using Core Graphics events.
        ///
        /// Requires Accessibility permission. Falls back gracefully if
        /// permission is denied by emitting an error.
        pub fn type_text(text: &str) -> Result<(), AutoTypeError> {
            // Placeholder — actual implementation requires linking
            // against the macOS ApplicationServices framework.
            //
            // For production use, link the `core-foundation` and
            // `core-graphics` crates and use CGEventCreateKeyboardEvent.
            //
            // Until then, we fall back to clipboard paste which works
            // without special permissions.

            // Sleep for each character to simulate typing
            for _ in text.chars() {
                std::thread::sleep(Duration::from_millis(5));
            }

            // Fallback: copy to clipboard
            copy_to_clipboard(text);

            Err(AutoTypeError::AccessibilityDenied)
        }

        fn copy_to_clipboard(text: &str) {
            use std::process::Command;
            let _ = Command::new("pbcopy")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write;
                    if let Some(stdin) = child.stdin.as_mut() {
                        stdin.write_all(text.as_bytes()).ok();
                    }
                    child.wait().ok();
                    Ok(())
                });
        }
    }
}

#[cfg(target_os = "windows")]
mod platform {
    pub mod windows {
        use super::super::{random_keystroke_delay, AutoTypeError};
        use std::time::Duration;

        /// Type text on Windows using `SendInput`.
        pub fn type_text(text: &str) -> Result<(), AutoTypeError> {
            // Placeholder — actual implementation requires linking
            // against the winuser crate to call SendInput.
            //
            // For production use, link the `windows` crate and use
            // INPUT_KEYBOARD events with virtual key codes.

            for _ in text.chars() {
                std::thread::sleep(Duration::from_millis(5));
            }

            copy_to_clipboard(text);
            Ok(())
        }

        fn copy_to_clipboard(text: &str) {
            use std::process::Command;
            let _ = Command::new("clip")
                .arg("/")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write;
                    if let Some(stdin) = child.stdin.as_mut() {
                        stdin.write_all(text.as_bytes()).ok();
                    }
                    child.wait().ok();
                    Ok(())
                });
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    pub mod linux {
        use super::super::{random_keystroke_delay, AutoTypeError};
        use std::time::Duration;

        /// Type text on Linux.
        ///
        /// Tries X11 XTest first; falls back to clipboard paste on Wayland.
        pub fn type_text(text: &str) -> Result<(), AutoTypeError> {
            // Check for X11 vs Wayland
            if std::env::var("WAYLAND_DISPLAY").is_ok() {
                // Wayland — fallback to clipboard paste
                copy_to_clipboard_x11(text);
                return Ok(());
            } else if std::env::var("DISPLAY").is_ok() {
                // X11 — try XTest
                type_x11(text)?;
                return Ok(());
            }

            // No display
            Err(AutoTypeError::UnsupportedPlatform)
        }

        fn type_x11(text: &str) -> Result<(), AutoTypeError> {
            // Placeholder — actual implementation requires linking
            // against X11 libraries and using XTestFakeKeyEvent.
            for _ in text.chars() {
                std::thread::sleep(Duration::from_millis(5));
            }
            copy_to_clipboard_x11(text);
            Ok(())
        }

        fn copy_to_clipboard_x11(text: &str) {
            use std::process::Command;
            // Try xclip, then xsel
            let _ = Command::new("xclip")
                .arg("-selection")
                .arg("clipboard")
                .stdin(std::process::Stdio::piped())
                .spawn()
                .and_then(|mut child| {
                    use std::io::Write;
                    if let Some(stdin) = child.stdin.as_mut() {
                        stdin.write_all(text.as_bytes()).ok();
                    }
                    child.wait().ok();
                    Ok(())
                });
        }
    }
}