// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Controler for the application

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

use crate::filter_store::{FilterStore, KeysasAuthorization, USBDevice};

use tauri::App;

pub struct AppControler {
    pub store: FilterStore
}

impl AppControler {
    pub fn init() -> AppControler {
        let mut ctrl = AppControler {
            store: FilterStore::init_store(),
        };

        // Create a default USB device for the tests
        let usb = USBDevice {
            name: String::from("Kingston USB"),
            path: String::from("D:"),
            authorization: KeysasAuthorization::AllowedRead,
            files: Vec::new(),
        };

        ctrl.store.add_device(&usb);

        ctrl
    }
}
