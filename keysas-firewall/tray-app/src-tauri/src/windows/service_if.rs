// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Implementation of the Service Interface for Windows

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

use anyhow::anyhow;
use serde::Serialize;
use std::sync::{Arc, RwLock};

use crate::app_controller::AppController;
use crate::service_if::{ServiceInterface, FileUpdateMessage, UsbUpdateMessage};

/// Handle to the service interface client and server
pub struct WindowsServiceInterface {
    server: Arc<RwLock<libmailslot::MailSlot>>,
}

/// Name of the communication pipe
const SERVICE_PIPE: &str = r"\\.\mailslot\keysas\service-to-app";
const TRAY_PIPE: &str = r"\\.\mailslot\keysas\app-to-service";

impl WindowsServiceInterface {
    pub fn init() -> Result<WindowsServiceInterface, anyhow::Error> {
        // Initialize the mailslot handles
        let server = match libmailslot::create_mailslot(SERVICE_PIPE) {
            Ok(s) => s,
            Err(e) => return Err(anyhow!("Failed to create server: {e}")),
        };

        Ok(WindowsServiceInterface {
            server: RwLock::new(server).into(),
        })
    }
}

impl ServiceInterface for WindowsServiceInterface {
    /// Start the server thread to listen for the Keysas service
    fn start_server(&self, ctrl: &Arc<AppController>) -> Result<(), anyhow::Error> {
        // Start listening on the server side
        let ctrl_hdl = ctrl.clone();
        let server = self.server.clone();
        std::thread::spawn(move || {
            // Get a mutable lock on the server
            let server = match server.write() {
                Ok(s) => s,
                Err(_) => {
                    return;
                }
            };
            println!("Start listening for daemon");
            loop {
                while let Ok(Some(msg)) = libmailslot::read_mailslot(&server) {
                    if let Ok(update) = serde_json::from_slice::<FileUpdateMessage>(msg.as_bytes())
                    {
                        ctrl_hdl.notify_file_change(&update);
                        println!("message from service {:?}", update);
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        });
        Ok(())
    }

    fn send_file_update(&self, update: &FileUpdateMessage) -> Result<(), anyhow::Error> {
        todo!()
    }

    fn send_usb_update(&self, update: &UsbUpdateMessage) -> Result<(), anyhow::Error> {
        let msg_vec = match serde_json::to_string(update) {
            Ok(m) => m,
            Err(e) => return Err(anyhow!("Failed to serialize message: {e}")),
        };

        if let Err(e) = libmailslot::write_mailslot(TRAY_PIPE, &msg_vec) {
            return Err(anyhow!("Failed to post message to the mailslot: {e}"));
        }

        Ok(())
    }
}