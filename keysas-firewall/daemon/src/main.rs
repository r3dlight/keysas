// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! KeysasDriverInterface is a generic interface to send and receive messages
//! to the firewall driver in kernel space.
//! The interface directs call to the Windows interface

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
#![forbid(private_in_public)]
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]

#![feature(vec_into_raw_parts)]
#![feature(str_split_remainder)]

pub mod driver_interface;
pub mod tray_interface;
pub mod controller;

use crate::controller::ServiceController;

use anyhow::anyhow;

fn main() -> Result<(), anyhow::Error> {
    // Initialize the logger
    simple_logger::init()?;

    // Initialize and start the service
    if let Err(e) = ServiceController::init() {
        log::error!("Failed to start the service: {e}");
        return Err(anyhow!("Failed to start the service: {e}"));
    }

    // Put the service in sleep until it receives request from the driver or the HMI

    loop {
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}
