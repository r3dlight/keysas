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
#![feature(vec_into_raw_parts)]
#![feature(is_some_and)]
#![feature(str_split_remainder)]

pub mod driver_interface;
pub mod windows_driver_interface;

use crate::driver_interface::init_driver_com;

use anyhow::anyhow;

fn main() -> Result<(), anyhow::Error> {
    // Initialize the logger
    simple_logger::init()?;

    // Initialize the connection with the driver
    if let Err(e) = init_driver_interface() {
        log::error!("Failed to initialize communications with driver: {e}");
        return Err(anyhow!("Error: Driver interface initialization failed"));
    }

    log::info!("Driver interface OK");

    loop {}
}

// Initialize the driver interface and register the callbacks
fn init_driver_interface() -> Result<(), anyhow::Error> {
    init_driver_com()?;
    Ok(())
}
