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
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};

use crate::app_controller::AppController;
use crate::service_if::{UsbUpdateMessage, FileUpdateMessage}

/// Handle to the service interface client and server
pub struct LinuxServiceInterface {}

impl LinuxServiceInterface {
    pub fn init() -> Result<LinuxServiceInterface, anyhow::Error> {
        todo!()
    }
}

impl ServiceInterface for LinuxServiceInterface {
    /// Start the server thread to listen for the Keysas service
    fn start_server(&self, ctrl: &Arc<AppController>) -> Result<(), anyhow::Error> {
        todo!()
    }

    
    fn send_file_update(&self, update: &FileUpdateMessage) -> Result<(), anyhow::Error> {
        todo!()
    }

    fn send_usb_update(&self, update: &UsbUpdateMessage) -> Result<(), anyhow::Error> {
        todo!()
    }
}