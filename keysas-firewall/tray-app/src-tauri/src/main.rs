// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Entry point for the USB Firewall administration panel

#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![forbid(private_in_public)]
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]
// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//mod service_if;
mod app_controler;
mod filter_store;

use tauri::{
    AppHandle, Manager, SystemTray, SystemTrayEvent, State
};
use tauri_plugin_positioner::{Position, WindowExt};

use crate::app_controler::AppControler;

use anyhow::anyhow;

/// Payload for the init event sent to the usb_details window
#[derive(Clone, serde::Serialize)]
struct InitPayload {
    /// Name of the USB device
    usb_name: String
}

fn main() -> Result<(), anyhow::Error> {
    // Initialize the logger
    simple_logger::init()?;

    // Launch the tauri application
    init_tauri()?;

    Ok(())
}

/// Initialize the tauri application as a system tray app
fn init_tauri() -> Result<(), anyhow::Error> {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_positioner::init())
        .manage(AppControler::init())
        .system_tray(SystemTray::new())
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick {
                position: _,
                size: _,
                ..
            } => {
                if let Err(e) = open_usb_view(app) {
                    log::error!("Failed to open main view: {e}");
                    app.exit(1);
                }
            }
            _ => {}
        })
        .invoke_handler(tauri::generate_handler![get_file_list])
        .build(tauri::generate_context!())?;

    app.run(|_app_handle, event| match event {
        tauri::RunEvent::ExitRequested { api, .. } => {
            api.prevent_exit();
        }
        _ => {}
    });

    Ok(())
}

/// Toggle the USB view when the tray icon is clicked
/// 
/// # Arguments
/// 
/// * 'app' - The tauri application
fn open_usb_view(app: &AppHandle) -> Result<(), anyhow::Error> {
    // Get the window
    match app.get_window("main") {
        Some(w) => {
            // If the window exists, toggle its visibility
            match w.is_visible()? {
                false => {
                    w.move_window(Position::BottomRight)?;
                    w.set_focus()?;
                    w.show()?;
                }
                true => {
                    w.hide()?;
                }
            }
        },
        None => {
            // If the window does not exists, create a new one
            let w = tauri::WindowBuilder::new(
                app,
                "main",
                tauri::WindowUrl::App("index.html".into())
            ).build()?;
            w.move_window(Position::BottomRight)?;
            w.set_decorations(false)?;
            w.set_focus()?;
        }
    };
    
    Ok(())
}

#[tauri::command]
fn get_file_list(usb_name: String, app_ctrl: State<AppControler>) -> Result<String, String> {
    match app_ctrl.store.get_files(&usb_name) {
        Ok(files) => Ok(String::from("Found files")),
        Err(e) => Err(String::from("Failed to get files"))
    }
}