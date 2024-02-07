// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! FileFilterInterface is a generic interface to send and receive messages
//! to the file filter in kernel space.
//! The interface must be specialized for Linux or Windows
//!
//! Communications between the controller and the file filter is as follows:
//! - On detection of a new file by the filter
//!
//! ```text
//!           Filter                                 Controller
//!           ──────                                 ───────────
//!  New file    │     authorize_file(FilteredFile)      │
//!  accessed    │ ────────────────────────────────────► │
//!              │             Auth_status               │ Check station report,
//!              │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│ file policy, asks user
//!              │                                       │
//! ```
//! The filter calls the controller with [authorize_file](crate::controller::ServiceController) to validate the
//!  new file. It must provide a [FilteredFile](crate::controller) with all the information on the
//!  file. The controller responds with a boolean indicating if the file is authorized or not.
//!
//! - Request by the controller to update file authorization status
//!
//! ```text
//!           Controller                                Filter
//!           ──────────                                ──────
//!               │     update_file_auth(FilteredFile)     │
//!               │ ─────────────────────────────────────► │
//!               │              Ok/error                  │ Update file control
//!               │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
//! ```
//! The controller can send a request to the filter to update the authorization
//!  status of a file.
//!
//! - Get the USB authorization status
//!
//! ```text
//!           Filter                                 Controller
//!           ──────                                 ──────────
//!              │         get_usb_auth(mount_point)      │
//!              │ ─────────────────────────────────────► │
//!              │            Auth_status/error           │ Check USB auth
//!              │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │
//! ```
//! The filter can request the authorization status for a USB device so that it 
//! can set the default policy for all files on the device. The request is done
//! with the mount point of the filesystem.

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

use cfg_if::cfg_if;
use std::boxed::Box;
use std::sync::{Arc, Mutex};

use crate::controller::{ServiceController, FilePolicy, UsbDevicePolicy};

#[cfg(target_os = "windows")]
use crate::windows::file_filter_if::WindowsFileFilterInterface;

#[cfg(target_os = "linux")]
use crate::linux::file_filter_if::LinuxFileFilterInterface;

pub struct FileFilterInterfaceBuilder {}

impl FileFilterInterfaceBuilder {
    pub fn build() -> Result<Box<dyn FileFilterInterface + Send + Sync>, anyhow::Error> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                return Ok(Box::new(LinuxFileFilterInterface::init()?)
                            as Box<dyn FileFilterInterface + Send + Sync>)
            } else if #[cfg(target_os = "windows")] {
                return Ok(Box::new(WindowsFileFilterInterface::init()?)
                            as Box<dyn FileFilterInterface + Send + Sync>)
            } else {
                return Err(anyhow!("OS not supported"));
            }
        }
    }
}

pub trait FileFilterInterface {
    /// Start listening for request on the interface
    ///
    /// # Arguments
    ///
    /// `ctrl` - Handle to the service controller
    fn start(&self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error>;

    /// Update the control policy on a file
    ///
    /// # Arguments
    ///
    /// `update` - Information on the file and the new authorization status
    fn update_file_auth(&self, update: &FilePolicy) -> Result<(), anyhow::Error>;

    /// Update the control policy on a partition
    ///
    /// # Arguments
    ///
    /// `update` - Information on the partition and the new authorization status, the mount point must be specified
    fn update_usb_auth(&self, update: &UsbDevicePolicy) -> Result<(), anyhow::Error>;

    /// Stop the interface and free resources
    fn stop(self: Box<Self>);
}
