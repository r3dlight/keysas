// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Generic interface to the Keysas daemon/Windows service. It must be specialized
//!  for Linux and Windows
//! 
//! Communications between the daemon and the tray app are:
//! 
//! - Notification of Usb device or File authorization update
//!
//!  ```text
//!           Daemon                        App
//!           ──────                       ─────
//!             │      FileUpdateMessage     │
//!             │ ─────────────────────────► │
//!             │                            │
//!             │      UsbUpdateMessage      │
//!             │ ─────────────────────────► │
//!             │                            │
//! ```
//! 
//! - Request by the user to update the authorization status for a Usb device or a File
//!
//! ```text
//!            App                         Daemon
//!           ─────                        ──────
//!             │      FileUpdateMessage     │
//!             │ ─────────────────────────► │
//!             │                            │
//!             │      UsbUpdateMessage      │
//!             │ ─────────────────────────► │
//!             │                            │
//! ```
//! 
//! Both type of communications are done with UpdateMessage

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

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use cfg_if::cfg_if;

use crate::app_controller::AppController;

#[cfg(target_os = "windows")]
use crate::windows::service_if::WindowsServiceInterface;

#[cfg(target_os = "linux")]
use crate::linux::service_if::LinuxServiceInterface;

/// Authorization states for USB devices
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum UsbAuthorization {
    /// Authorization request pending
    Pending = 0,
    /// Access is blocked
    Block,
    /// Access is allowed in read mode only
    AllowRead,
    /// Access is allowed with a warning to the user
    AllowRW,
    /// Access is allowed for all operations
    AllowAll,
}

impl UsbAuthorization {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Authorization states for files
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum FileAuthorization {
    /// Authorization request pending
    Pending = 0,
    /// Access is blocked
    Block,
    /// Access is allowed in read mode only
    AllowRead,
    /// Access is allowed in read/write mode
    AllowRW,
}

impl FileAuthorization {
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Convert u8 to FileAuthorization, default value is Block
    pub fn from_u8(auth: u8) -> FileAuthorization {
        match auth {
            0 => FileAuthorization::Pending,
            1 => FileAuthorization::Block,
            2 => FileAuthorization::AllowRead,
            3 => FileAuthorization::AllowRW,
            _ => FileAuthorization::Block
        }
    }
}

/// Message for a file status notification
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileUpdateMessage {
    pub device: String,
    pub id: [u16; 16],
    pub path: String,
    pub authorization: FileAuthorization,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UsbUpdateMessage {
    pub device: String,
    pub path: String,
    pub name: String,
    pub authorization: UsbAuthorization
}

#[derive(Debug, Copy, Clone)]
pub struct ServiceInterfaceBuilder {}

impl ServiceInterfaceBuilder {
    pub fn build() -> Result<Box<dyn ServiceInterface + Send + Sync>, anyhow::Error> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                return Ok(Box::new(LinuxServiceInterface::init()?)
                            as Box<dyn ServiceInterface + Send + Sync>)
            } else if #[cfg(target_os = "windows")] {
                return Ok(Box::new(WindowsServiceInterface::init()?)
                            as Box<dyn ServiceInterface + Send + Sync>)
            } else {
                return Err(anyhow!("OS not supported"))
            }
        }
    }
}

/// Generice Service Interface
pub trait ServiceInterface {
    fn start_server(&self, ctrl: &Arc<AppController>) -> Result<(), anyhow::Error>;

    fn send_file_update(&self, update: &FileUpdateMessage) -> Result<(), anyhow::Error>;

    fn send_usb_update(&self, update: &UsbUpdateMessage) -> Result<(), anyhow::Error>;
}