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
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]
// Prevents additional console window on Windows in release, DO NOT REMOVE!!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app_controller;
mod filter_store;
mod service_if;

use anyhow::anyhow;
use std::sync::Arc;
use tauri::{
    AppHandle, LogicalPosition, LogicalSize, Manager, PhysicalPosition, State, SystemTray,
    SystemTrayEvent, Window,
};

use crate::app_controller::AppController;
use crate::service_if::KeysasAuthorization;

/// Payload for the init event sent to the usb_details window
#[derive(Clone, serde::Serialize)]
struct InitPayload {
    /// Name of the USB device
    usb_name: String,
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
        .setup(|app| {
            app.manage(AppController::init(app.handle())?);
            Ok(())
        })
        .system_tray(SystemTray::new())
        .on_system_tray_event(|app, event| {
            if let SystemTrayEvent::LeftClick { position, .. } = event {
                if let Err(e) = open_usb_view(app, &position) {
                    log::error!("Failed to open main view: {e}");
                    app.exit(1);
                }
            }
        })
        .invoke_handler(tauri::generate_handler![get_file_list, toggle_file_auth])
        .build(tauri::generate_context!())?;

    app.run(|_app_handle, event| {
        if let tauri::RunEvent::ExitRequested { api, .. } = event {
            api.prevent_exit();
        }
    });

    Ok(())
}

/// Set the application on the bottom right corner over the desktop tray
///
/// # Arguments
///
/// * 'w' - Reference to the window
/// * 'click' - Position of the click event, it corresponds to the top of the icon in the tray
fn set_window_over_tray(w: &Window, click: &PhysicalPosition<f64>) -> Result<(), anyhow::Error> {
    let screen = w
        .current_monitor()?
        .ok_or_else(|| anyhow!("Not screen detected"))?;
    let scale_factor = screen.scale_factor();

    // Click position corresponds to the top left corner of the icon
    // Convert the click physical position to logical
    let click_log = click.to_logical::<f64>(scale_factor);

    let screen_pos_log = screen.position().to_logical::<f64>(scale_factor);
    let screen_size_log = screen.size().to_logical::<f64>(scale_factor);

    // Set arbitrary size for the window
    // TODO: adapt it to the monitor scale factor
    let window_size = LogicalSize::<f64>::new(400.0, 300.0);
    w.set_size(window_size)?;

    // Set the position of the window just above the click position and the farthest to the right
    let x_log = if click_log.x + window_size.width <= screen_pos_log.x + screen_size_log.width {
        click_log.x
    } else {
        screen_pos_log.x + screen_size_log.width - window_size.width
    };
    let window_pos = LogicalPosition::<f64>::new(x_log, click_log.y - window_size.height);
    w.set_position(window_pos)?;

    Ok(())
}

/// Toggle the USB view when the tray icon is clicked
///
/// # Arguments
///
/// * 'app' - The tauri application
fn open_usb_view(app: &AppHandle, click: &PhysicalPosition<f64>) -> Result<(), anyhow::Error> {
    // Get the window
    match app.get_window("main") {
        Some(w) => {
            // If the window exists, toggle its visibility
            match w.is_visible()? {
                false => {
                    set_window_over_tray(&w, click)?;
                    w.set_focus()?;
                    w.show()?;
                }
                true => {
                    w.hide()?;
                }
            }
        }
        None => {
            // If the window does not exists, create a new one
            let w =
                tauri::WindowBuilder::new(app, "main", tauri::WindowUrl::App("index.html".into()))
                    .decorations(false)
                    .focused(true)
                    .build()?;
            set_window_over_tray(&w, click)?;
        }
    };

    Ok(())
}

/// Command to retrieve list of all the files in a USB device
/// The list is returned as a json array of File object as follows
/// [{
///     device: string,
///     path: string
///     authorization: boolean
/// }, ..]
///
/// # Arguments
///
/// * 'device_path' - Name of the path of the volume, e.g 'D:'
/// * 'app_ctrl' - Handle to the application controler, it is supplied by tauri
#[tauri::command]
async fn get_file_list(
    device_path: String,
    app_ctrl: State<'_, Arc<AppController>>,
) -> Result<String, String> {
    match app_ctrl.get_file_list(&device_path) {
        Ok(files) => match serde_json::to_string(&files) {
            Ok(s) => Ok(s),
            Err(e) => {
                log::error!("Failed to serialize result: {e}");
                Err(String::from("Failed to get files"))
            }
        },
        Err(e) => {
            log::error!("Device not found: {e}");
            Err(String::from("Failed to get files"))
        }
    }
}

/// Request to toggle the authorization for a file in a give device
///
/// # Arguments
///
/// * 'device' - Name of the USB device volume, e.g. 'D:'
/// * 'path' - Full path to the file on the device
/// * 'current_auth' - Current authorization status for the file
#[tauri::command]
async fn toggle_file_auth(
    device: String,
    id: [u16; 16],
    path: String,
    new_auth: u8,
    app_ctrl: State<'_, Arc<AppController>>,
) -> Result<(), String> {
    let auth = KeysasAuthorization::from_u8_file(new_auth);
    println!("Test");
    if let Err(e) = app_ctrl.request_file_auth_toggle(&device, &id, &path, auth) {
        println!("toggle_file_auth: File toggle failed: {e}");
        return Err(e.to_string());
    }
    Ok(())
}
