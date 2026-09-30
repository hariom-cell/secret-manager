//! System tray integration — quick access from the menu bar / system tray.
//!
//! Provides:
//! - Lock vault from tray menu
//! - Quick unlock (re-prompt for password)
//! - Show/hide the main window
//! - Quit
//!
//! The tray icon provides a subtle hint that the app is running, allowing
//! the user to lock quickly when stepping away from the device.

use tauri::{
    menu::{MenuBuilder, MenuItemBuilder},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager,
};

/// Set up the system tray icon with menu.
pub fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    let lock_item = MenuItemBuilder::new("Lock Vault", "lock_vault")
        .build(app)?;
    let show_item = MenuItemBuilder::new("Show Window", "show_window")
        .build(app)?;
    let separator = tauri::menu::PredefinedMenuItem::separator(app)?;
    let quit_item = MenuItemBuilder::new("Quit", "quit")
        .build(app)?;

    let menu = MenuBuilder::new(app)
        .items(&[&show_item, &lock_item, &separator, &quit_item])
        .build()?;

    let tray = TrayIconBuilder::new()
        .tooltip("Secret Manager — locked")
        .icon(app.default_window_icon().cloned().unwrap_or_else(|| {
            tauri::image::Image::from_bytes(&[])
                .unwrap_or_else(|_| tauri::image::Image::new_owned(vec![0u8; 16], 1, 1))
        }))
        .menu(&menu)
        .menu_on_left_click(false)
        .on_menu_event(|app, event| {
            match event.id().as_ref() {
                "lock_vault" => {
                    // Send lock event to the main window
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.emit("tray-lock", ());
                    }
                }
                "show_window" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                "quit" => {
                    app.exit(0);
                }
                _ => {}
            }
        })
        .on_tray_icon_event(|tray, event| {
            // Left click shows the window
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                let app = tray.app_handle();
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(())
}