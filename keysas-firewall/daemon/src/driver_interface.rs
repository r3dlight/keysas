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

use crate::windows_driver_interface::WindowsDriverInterface;

use anyhow::anyhow;

fn request_callback() {
    log::info!("Called!");
}

/// Initiliaze the driver interface depending on the OS
pub fn init_driver_com() -> Result<WindowsDriverInterface, anyhow::Error> {
    if cfg!(windows) {
        let driver_interface = WindowsDriverInterface::open_driver_com()?;

        driver_interface.start_driver_com(request_callback)?;

        Ok(driver_interface)
    } else {
        log::error!("OS not supported");
        Err(anyhow!("Failed to open driver interface: OS not supported"))
    }
}
