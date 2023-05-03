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
    App, CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu, SystemTrayMenuItem,
};
use tauri_plugin_positioner::{Position, WindowExt};

use crate::app_controler::AppControler;

/// Command call to open the USB device window
///
/// # Arguments
///
/// * 'app' - Handle to the tauri app, supplied by tauri
/// * 'name' - Name of the USB device selected, supplied by the frontend
#[tauri::command]
fn show_usb_device(app: tauri::AppHandle, name: &str) {
    tauri::WindowBuilder::new(
        &app,
        "usbDetails",
        tauri::WindowUrl::App("usb_details.html".into())
    ).build().unwrap();
}

fn main() -> Result<(), anyhow::Error> {
    // Launch the tauri application
    init_tauri()?;

    Ok(())
}

// Initialize the tauri application as a system tray app
fn init_tauri() -> Result<(), anyhow::Error> {
    let quit = CustomMenuItem::new("quit".to_string(), "Quit");
    let hide = CustomMenuItem::new("hide".to_string(), "Hide");
    let tray_menu = SystemTrayMenu::new()
        .add_item(quit)
        .add_native_item(SystemTrayMenuItem::Separator)
        .add_item(hide);
    let tray = SystemTray::new().with_menu(tray_menu);

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_positioner::init())
        .manage(AppControler::init())
        .invoke_handler(tauri::generate_handler![show_usb_device])
        .system_tray(tray)
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::LeftClick {
                position: _,
                size: _,
                ..
            } => {
                println!("Left click event");
                let window = app.get_window("main").unwrap();
                match window.is_visible() {
                    Ok(false) => {
                        window.move_window(Position::BottomRight);
                        window.show();
                    }
                    Ok(true) => {
                        window.hide();
                    }
                    _ => {}
                }
            }
            SystemTrayEvent::RightClick {
                position: _,
                size: _,
                ..
            } => {
                println!("Right click event");
            }
            SystemTrayEvent::DoubleClick {
                position: _,
                size: _,
                ..
            } => {
                println!("Double click event");
            }
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "quit" => {
                    println!("Quit selected");
                }
                "hide" => {
                    println!("Hide selected");
                }
                _ => {}
            },
            _ => {}
        })
        .build(tauri::generate_context!())?;

    app.run(|_app_handle, event| match event {
        tauri::RunEvent::ExitRequested { api, .. } => {
            api.prevent_exit();
        }
        _ => {}
    });

    Ok(())
}
