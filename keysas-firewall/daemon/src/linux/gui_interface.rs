// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Linux implementation of the interface to the user graphical interface

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

use std::sync::{Arc, Mutex};

use crate::controller::ServiceController;
use crate::gui_interface::{FileUpdateMessage, GuiInterface, UsbUpdateMessage};

#[derive(Debug, Copy, Clone)]
pub struct LinuxGuiInterface {}

impl LinuxGuiInterface {
    pub fn init() -> Result<LinuxGuiInterface, anyhow::Error> {
        // let ctrl_hdl = ctrl.clone();
        // // Initialize the server in a separate thread
        // std::thread::spawn(move || {
        //     let server = match libmailslot::create_mailslot(TRAY_PIPE) {
        //         Ok(s) => s,
        //         Err(_) => return,
        //     };

        //     loop {
        //         while let Ok(Some(msg)) = libmailslot::read_mailslot(&server) {
        //             if let Ok(update) = serde_json::from_slice::<FileUpdateMessage>(msg.as_bytes()) {
        //                 println!("message from tray {:?}", update);
        //                 if let Err(e) = ctrl_hdl.handle_tray_request(&update) {
        //                     println!("Failed to handle tray request: {e}");
        //                 }
        //             }
        //         }
        //         std::thread::sleep(std::time::Duration::from_secs(1));
        //     }
        // });
        Ok(LinuxGuiInterface {})
    }
}

impl GuiInterface for LinuxGuiInterface {
    /// Start listening for messages coming from the user
    fn start(&mut self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error> {
        todo!()
    }

    /// Send a file update notification to the user
    ///
    /// # Arguments
    ///
    /// * `update` - File update message
    fn send_file_update(&self, update: FileUpdateMessage) -> Result<(), anyhow::Error> {
        todo!()
    }

    /// Send a usb update notification to the user
    ///
    /// # Arguments
    ///
    /// * `update` - USB update message
    fn send_usb_update(&self, update: UsbUpdateMessage) -> Result<(), anyhow::Error> {
        todo!()
    }

    /// Send a request to the user to authorize a file
    ///
    /// # Arguments
    ///
    /// * `file` - Contains information on the file and the requested authorization
    fn request_file_auth(&self, file: FileUpdateMessage) -> Result<bool, anyhow::Error> {
        todo!()
    }

    /// Send a request to the user to authorize a usb key
    ///
    /// # Arguments
    ///
    /// * `usb` - Contains information on the usb key and the requested authorization
    fn request_usb_auth(&self, usb: UsbUpdateMessage) -> Result<bool, anyhow::Error> {
        todo!()
    }

    /// Stop listening for user notifications and free the interface
    fn stop(self: Box<Self>) {
        todo!()
    }
}
