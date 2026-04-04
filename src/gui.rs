//! Tauri-based Desktop UI for EdgeClaw
//!
//! Provides the window management and native system integration
//! for the EdgeClaw agent dashboard.

use tauri::{CustomMenuItem, SystemTray, SystemTrayMenu, SystemTrayMenuItem, SystemTrayEvent, Manager};
use std::sync::Arc;
use crate::AgentEngine;

/// Starts the Tauri GUI application and blocks the main thread.
///
/// This function will:
/// 1. Initialize the Tauri builder
/// 2. Setup the system tray
/// 3. Create the main window
/// 4. Register commands
pub fn run_gui(engine: Arc<AgentEngine>, webui_url: String) {
    let quit = CustomMenuItem::new("quit".to_string(), "Quit EdgeClaw");
    let show = CustomMenuItem::new("show".to_string(), "Show Dashboard");
    let tray_menu = SystemTrayMenu::new()
        .add_item(show)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(quit);

    let system_tray = SystemTray::new()
        .with_menu(tray_menu);

    tauri::Builder::default()
        .manage(engine)
        .manage(webui_url.clone())
        .system_tray(system_tray)
        .on_system_tray_event(move |app, event| {
            match event {
                SystemTrayEvent::LeftClick { .. } => {
                    let window = app.get_window("main").unwrap();
                    window.show().unwrap();
                    window.set_focus().unwrap();
                }
                SystemTrayEvent::MenuItemClick { id, .. } => {
                    match id.as_str() {
                        "quit" => {
                            std::process::exit(0);
                        }
                        "show" => {
                            let window = app.get_window("main").unwrap();
                            window.show().unwrap();
                            window.set_focus().unwrap();
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        })
        .setup(move |app| {
            let window = app.get_window("main").unwrap();
            
            // Navigate to the local WebUI server
            // In a production bundle, Tauri serves files itself, but for this agent
            // we link it to the embedded backend for full-feature parity.
            window.eval(&format!("window.location.href = '{}'", webui_url)).unwrap();
            
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[tauri::command]
pub fn get_agent_status(engine: tauri::State<Arc<AgentEngine>>) -> String {
    format!("EdgeClaw Agent — Online (Identity: {})", engine.get_identity().unwrap().device_id)
}
