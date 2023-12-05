// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Windows implementation of the interface to the user graphical interface

#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]
#![warn(trivial_numeric_casts)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]

use std::sync::{Arc, Mutex, RwLock};
use anyhow::anyhow;
use log::*;
use rust_i18n::t;

use windows::core::PCSTR;
use windows::Win32::UI::WindowsAndMessaging::*;

use crate::controller::{ServiceController, FileAuthorization, UsbAuthorization};
use crate::gui_interface::{FileUpdateMessage, GuiInterface, UsbUpdateMessage};

/// Name of the communication pipe
const SERVICE_PIPE: &str = r"\\.\mailslot\keysas\service-to-app";
const TRAY_PIPE: &str = r"\\.\mailslot\keysas\app-to-service";

#[derive(Debug)]
pub struct WindowsGuiInterface {
    is_running: Arc<RwLock<bool>>
}

impl WindowsGuiInterface {
    pub fn init() -> Result<WindowsGuiInterface, anyhow::Error> {
        Ok(WindowsGuiInterface {
            is_running: Arc::new(RwLock::new(false))
        })
    }
}

impl GuiInterface for WindowsGuiInterface {
    /// Start listening for messages coming from the user
    fn start(&mut self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error> {
        // Initialize the server in a separate thread
        {
            let mut running = self.is_running.write().unwrap();
            *running = true;
        }

        let stop = self.is_running.clone();
        let ctrl_hdl = ctrl.clone();

        std::thread::spawn(move || {
            let server = match libmailslot::create_mailslot(TRAY_PIPE) {
                Ok(s) => s,
                Err(_) => return,
            };

            loop {
                while let Ok(Some(msg)) = libmailslot::read_mailslot(&server) {
                    // Try to read a file update message
                    if let Ok(update) = serde_json::from_slice::<FileUpdateMessage>(msg.as_bytes()) {
                        {
                            let controller = ctrl_hdl.lock().unwrap();
                            if let Err(e) = controller.request_file_update(&update) {
                                error!("Failed to handle file update request: {e}");
                            }
                        }
                    }
                    // Try to read a usb update message
                    else if let Ok(update) = serde_json::from_slice::<UsbUpdateMessage>(msg.as_bytes()) {
                        {
                            let controller = ctrl_hdl.lock().unwrap();
                            if let Err(e) = controller.request_usb_update(&update) {
                                error!("Failed to handle usb update request: {e}");
                            }
                        }
                    } else {
                        warn!("Message from tray app not recognized");
                    }
                }

                // Test if the process is still alive
                {
                    let must_stop = stop.read().unwrap();
                    if *must_stop {
                        return ;
                    }
                }

                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        });

        Ok(())
    }

    /// Send a file update notification to the user
    ///
    /// # Arguments
    ///
    /// * `update` - File update message
    fn send_file_update(&self, update: &FileUpdateMessage) -> Result<(), anyhow::Error> {
        let msg_vec = match serde_json::to_string(update) {
            Ok(m) => m,
            Err(e) => return Err(anyhow!("Failed to serialize message: {e}")),
        };
    
        if let Err(e) = libmailslot::write_mailslot(SERVICE_PIPE, &msg_vec) {
            return Err(anyhow!("Failed to post message to the mailslot: {e}"));
        }

        Ok(())
    }

    /// Send a usb update notification to the user
    ///
    /// # Arguments
    ///
    /// * `update` - USB update message
    fn send_usb_update(&self, update: &UsbUpdateMessage) -> Result<(), anyhow::Error> {
        let msg_vec = match serde_json::to_string(update) {
            Ok(m) => m,
            Err(e) => return Err(anyhow!("Failed to serialize message: {e}")),
        };
    
        if let Err(e) = libmailslot::write_mailslot(SERVICE_PIPE, &msg_vec) {
            return Err(anyhow!("Failed to post message to the mailslot: {e}"));
        }

        Ok(())
    }

    /// Send a request to the user to authorize a file
    ///
    /// # Arguments
    ///
    /// * `file` - Contains information on the file and the requested authorization
    fn request_file_auth(&self, file: &FileUpdateMessage) -> Result<bool, anyhow::Error> {
        let auth_request = match file.authorization {
            FileAuthorization::AllowRead => {
                t!("user_file_auth_read_req", "path" => file.path, "usb" => file.device)
            },
            FileAuthorization::AllowRW => {
                t!("user_file_auth_write_req", "path" => file.path, "usb" => file.device)
            }
            _ => {
                return Err(anyhow!("Unvalid authorization request"));
            }
        };

        display_auth_request(PCSTR::from_raw(auth_request.as_ptr()))
    }

    /// Send a request to the user to authorize a usb key
    ///
    /// # Arguments
    ///
    /// * `usb` - Contains information on the usb key and the requested authorization
    fn request_usb_auth(&self, usb: &UsbUpdateMessage) -> Result<bool, anyhow::Error> {
        let auth_request = match usb.authorization {
            UsbAuthorization::AllowRead => {
                t!("user_usb_auth_read_req", "mount" => usb.path, "usb" => usb.name)
            },
            UsbAuthorization::AllowRW => {
                t!("user_usb_auth_write_req", "mount" => usb.path, "usb" => usb.name)
            },
            UsbAuthorization::AllowAll => {
                t!("user_usb_auth_all_req", "mount" => usb.path, "usb" => usb.name)
            },
            _ => {
                return Err(anyhow!("Unvalid authorization request"));
            }
        };

        display_auth_request(PCSTR::from_raw(auth_request.as_ptr()))
    }

    /// Stop listening for user notifications and free the interface
    fn stop(self: Box<Self>) {
        // Signal the mailslot thread to stop
        let mut running = self.is_running.write().unwrap();
        *running = false;
    }
}

fn display_auth_request(request: PCSTR) -> Result<bool, anyhow::Error> {
    match unsafe {
        MessageBoxA(
            None,
            request,
            PCSTR::from_raw(t!("keysas_title").as_ptr()),
            MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL,
        )
    } {
        IDYES => Ok(true),
        IDNO => Ok(false),
        status => Err(anyhow!(format!(
            "Unknown Authorization: {:?}",
            status
        ))),
    }
}