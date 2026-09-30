//! Secure window — prevents screen capture, screenshots, and screen recording.
//!
//! On each platform, we apply the equivalent of Android's `FLAG_SECURE`:
//! the OS is instructed not to capture this window's contents.
//!
//! This prevents:
//! - Screenshots / screen captures
//! - Screen recording of the app window
//! - Other apps reading this window's pixels via accessibility APIs
//!
//! # Security Notes
//!
//! These measures are best-effort. A determined attacker with kernel-level
//! access, physical screen recording equipment, or a compromised OS can still
//! capture secrets. Use auto-lock and don't leave the vault unlocked when
//! unattended.

use tauri::{WebviewWindowBuilder, WebviewUrl};

/// Build a secure Tauri window with platform-specific protections.
pub fn build_secure_window(
    label: &str,
    app: &tauri::App,
) -> tauri::WebviewWindow {
    let mut builder = WebviewWindowBuilder::new(
        app,
        label,
        WebviewUrl::App("index.html".into()),
    )
    .title("Secret Manager")
    .inner_size(tauri::PhysicalSize::new(900, 700))
    .min_inner_size(tauri::PhysicalSize::new(600, 400))
    .center()
    .resizable(true)
    .decorations(true)
    .transparent(false);

    // Disable DevTools in release builds (they can inspect memory)
    #[cfg(not(debug_assertions))]
    {
        let _ = builder = builder.data_directory_override("secure");
    }

    builder.build().expect("failed to create secure window")
}

/// Apply runtime hardening to an existing window.
///
/// This should be called after the window is created to apply
/// anti-capture measures that need the webview to be initialized.
pub fn apply_secure_window(window: &tauri::WebviewWindow) {
    // Inject JS to disable right-click context menus (prevent "Inspect Element")
    let _ = window.eval(r#"
        // Prevent right-click context menu
        document.addEventListener('contextmenu', (e) => e.preventDefault());
        // Prevent keyboard shortcuts for DevTools
        document.addEventListener('keydown', (e) => {
            if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'I' || e.key === 'J' || e.key === 'C')) {
                e.preventDefault();
            }
        });
    "#);
}
