// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! USB monitor is a generic interface to watch USB event and send them to the
//! controller
//! The interface must be specialized for Linux or Windows
//!
//! The usb monitor must run its own thread to watch usb kernel event.
//!
//! Communications between the controller and the monitor is as follows:
//! - On detection of a new Usb by the monitor
//!
//! ```text
//!           Monitor                                Controller
//!           ───────                                ───────────
//!  New USB     │     authorize_usb(UsbDevice, sig)     │
//!  key         │ ────────────────────────────────────► │
//!              │             Auth_status               │ Check sig and usb policy,
//!              │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│ asks user
//!              │                                       │
//!  ┌───────────┼───────────────────────────────────────┼─────────────┐
//!  │alt│ [Auth = true]                                 │             │
//!  │───┘       │                                       │             │
//!  │ Allow USB │        update_usb(UsbDevice)          │             │
//!  │ mounting  │ ────────────────────────────────────► │             │
//!  └─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘
//!  │ [Auth = false]                                    │             │
//!  │           │ If possible prevent Usb               │             │
//!  │           │ mounting, if not send an              │             │
//!  │           │ update.                               │             │
//!  │           │        update_usb(UsbDevice)          │             │
//!  │           │ ────────────────────────────────────► │             │
//!  └───────────┼───────────────────────────────────────┼─────────────┘
//! ```
//! The USB monitor calls the controller with [authorize_usb](crate::controller::ServiceController) to validate the
//!  new USB key. It must provide a [UsbDevice] with all the information on the
//!  key and if available the signature block found. If the mount point is knwown
//!  at that point it can be provided. The controller responds with a boolean
//!  indicating if the key is authorized or not.
//! The monitor sends further update to the monitor once the partition on the USB
//!  key is mounted with the same [device_id](crate::controller::UsbDevice) and the updated fields
//!
//! - Request by the controller to update usb key authorization status
//!
//! ```text
//!           Controller                                Monitor
//!           ──────────                                ───────
//!               │     update_usb_auth(UsbDevice)         │
//!               │ ─────────────────────────────────────► │
//!               │              Ok/error                  │ if possible update
//!               │ ◄─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ │ mount state of the
//!               │                                        │ usb key
//! ```
//! The controller can send a request to the monitor to update the mount state
//!  of the USB key partition. It it is possible the monitor will do it, otherwise
//!  it responds with an error.
//!

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

use crate::controller::{ServiceController, UsbDevice};

#[cfg(target_os = "windows")]
use crate::windows::usb_monitor::WindowsUsbMonitor;

#[cfg(target_os = "linux")]
use crate::linux::usb_monitor::LinuxUsbMonitor;

#[derive(Debug, Copy, Clone)]
pub struct UsbMonitorBuilder {}

impl UsbMonitorBuilder {
    pub fn build() -> Result<Box<dyn UsbMonitor + Send + Sync>, anyhow::Error> {
        cfg_if! {
            if #[cfg(target_os = "linux")] {
                return Ok(Box::new(LinuxUsbMonitor::init()?)
                            as Box<dyn UsbMonitor + Send + Sync>)
            } else if #[cfg(target_os = "windows")] {
                return Ok(Box::new(WindowsUsbMonitor::init()?)
                            as Box<dyn UsbMonitor + Send + Sync>)
            } else {
                return Err(anyhow!("OS not supported"))
            }
        }
    }
}

pub trait UsbMonitor {
    /// Start the monitor and register an handle to the controller
    ///
    /// # Arguments
    ///
    /// `ctrl` - Handle to the controller
    fn start(&self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error>;

    /// Update a usb policy
    ///
    /// # Arguments
    ///
    /// `update` - Information on the usb key and the new authorization status
    fn update_usb_auth(&self, update: &UsbDevice) -> Result<(), anyhow::Error>;

    /// Stop the monitor
    fn stop(self: Box<Self>);
}
