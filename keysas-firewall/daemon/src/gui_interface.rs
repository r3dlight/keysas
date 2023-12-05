// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Generic interface to the user graphical interface
//!
//! Communications between the daemon and the user are of three kinds:
//! - Notifications from the daemon to the user
//!
//! ```text
//!         Controller                                     GUI
//!         ──────────                                    ─────
//!             │     send_file_update(FileUpdateMessage)   │
//!             │ ────────────────────────────────────────► │
//!             │                                           │
//!             │     send_usb_update(UsbUpdateMessage)     │
//!             │ ────────────────────────────────────────► │
//!             │                                           │
//! ```
//! The notification contains a [FileUpdateMessage] or [UsbUpdateMessage] to
//! inform the user of the detection, removal or update of file (usb respectively)
//! in the firewall.
//!
//! - Authorization request from the daemon to the user
//!
//! ```text
//!         Controller                                      GUI
//!         ──────────                                     ─────
//!              │     request_usb_auth(UsbUpdateMessage)    │
//!              │ ────────────────────────────────────────► │
//!              │                   Yes/No                  │
//!              │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
//!              │                                           │
//!              │     request_file_auth(FileUpdateMessage)  │
//!              │ ────────────────────────────────────────► │
//!              │                   Yes/No                  │
//!              │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│
//! ```
//! The request is formulated by the daemon with a [UsbUpdateMessage] or
//! [FileUpdateMessage] with all the known information about the object and the
//! current authorization status set to Pending. Also the request contains the
//! new authorization status requested from the user. The users' response is a
//! boolean indicating the approval state of the request.
//!
//! - Authorization update from the user to the daemon
//!
//! ```text
//!            GUI                                      Controller
//!           ─────                                     ──────────
//!             │    request_usb_update(UsbUpdateMessage)    │
//!             │ ─────────────────────────────────────────► │
//!             │                 Ok / error                 │
//!             │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
//!             │                                            │
//!             │   request_file_update(FileUpdateMessage)   │
//!             │ ─────────────────────────────────────────► │
//!             │                 Ok / error                 │
//!             │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
//! ```
//! The request of the user contains a [UsbUpdateMessage] or [FileUpdateMessage]
//!  with the new authorization status set by the user. The daemon acknowledge the
//! change or send an error message.

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

use crate::controller::{FileAuthorization, ServiceController, UsbAuthorization};
use cfg_if::cfg_if;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[cfg(target_os = "windows")]
use crate::windows::gui_interface::WindowsGuiInterface;

#[cfg(target_os = "linux")]
use crate::linux::gui_interface::LinuxGuiInterface;

/// Message for a USB status notification
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UsbUpdateMessage {
    /// Usb device system identifier
    pub device: String,
    /// Mount point for the partition on the device
    pub path: String,
    /// Usb device name made from vendor, model, revision and serial number
    pub name: String,
    /// Authorization status
    pub authorization: UsbAuthorization,
}

/// Message for a file notification
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FileUpdateMessage {
    /// Usb device identifier
    pub device: String,
    /// File ID based on sha-256 hash of full path
    pub id: [u16; 16],
    /// Path to the file
    pub path: String,
    /// Authorization status
    pub authorization: FileAuthorization,
}

#[derive(Debug, Copy, Clone)]
pub struct GuiInterfaceBuilder {}

impl GuiInterfaceBuilder {
    pub fn build() -> Result<Box<dyn GuiInterface + Send + Sync>, anyhow::Error> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                return Ok(Box::new(LinuxGuiInterface::init()?)
                            as Box<dyn GuiInterface + Send + Sync>)
            } else if #[cfg(target_os = "windows")] {
                return Ok(Box::new(WindowsGuiInterface::init()?)
                            as Box<dyn GuiInterface + Send + Sync>)
            } else {
                return Err(anyhow!("OS not supported"))
            }
        }
    }
}

/// Generic User Interface
pub trait GuiInterface {
    /// Start listening for messages coming from the user
    ///
    /// # Arguments
    ///
    /// * `ctrl` - Handle to the service controller
    fn start(&mut self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error>;

    /// Send a file update notification to the user
    ///
    /// # Arguments
    ///
    /// * `update` - File update message
    fn send_file_update(&self, update: &FileUpdateMessage) -> Result<(), anyhow::Error>;

    /// Send a usb update notification to the user
    ///
    /// # Arguments
    ///
    /// * `update` - USB update message
    fn send_usb_update(&self, update: &UsbUpdateMessage) -> Result<(), anyhow::Error>;

    /// Send a request to the user to authorize a file
    ///
    /// # Arguments
    ///
    /// * `file` - Contains information on the file and the requested authorization
    fn request_file_auth(&self, file: &FileUpdateMessage) -> Result<bool, anyhow::Error>;

    /// Send a request to the user to authorize a usb key
    ///
    /// # Arguments
    ///
    /// * `usb` - Contains information on the usb key and the requested authorization
    fn request_usb_auth(&self, usb: &UsbUpdateMessage) -> Result<bool, anyhow::Error>;

    /// Stop listening for user notifications and free the interface
    fn stop(self: Box<Self>);
}

pub fn send_file_auth_status(
    _file_data: &[u16],
    _authorization: UsbAuthorization,
) -> Result<(), anyhow::Error> {
    todo!()
    // let file_path = match String::from_utf16(&file_data[17..]) {
    //     Ok(path) => path,
    //     Err(_) => {
    //         println!("Failed to convert request to string");
    //         return Err(anyhow!("Failed to convert request to string"));
    //     }
    // };
    // let file_path = file_path.trim_matches(char::from(0));

    // let mut id: [u16; 16] = Default::default();
    // id.copy_from_slice(&file_data[1..17]);

    // let msg = FileUpdateMessage {
    //     device: String::from("D:"),
    //     id,
    //     path: String::from(file_path),
    //     authorization,
    // };

    // send(&msg)
}
