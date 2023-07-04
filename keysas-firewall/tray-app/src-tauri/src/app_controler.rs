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

use crate::filter_store::{FileAuth, FilterStore, KeysasAuthorization, USBDevice};
use crate::service_if::{ServiceIf, FileUpdateMessage};

use anyhow::anyhow;
use std::sync::{Arc, RwLock};
use tauri::{AppHandle, Manager};

/// Application controler object, it contains handle to the application main services
pub struct AppControler {
    pub store: RwLock<FilterStore>,
    view: AppHandle,
    comm: ServiceIf
}

impl AppControler {
    /// Initialize the application controler
    /// It initialize
    ///     - the application data store
    ///     - the communication interface to the Keysas service
    ///     - store an handle to the view
    pub fn init(app_handle: AppHandle) -> Result<Arc<AppControler>, anyhow::Error> {
        // Create the application controler
        let ctrl = Arc::new(AppControler {
            store: RwLock::new(FilterStore::init_store()),
            view: app_handle,
            comm: ServiceIf::init_service_if()?
        });
        
        // Start the server thread
        if let Err(e) = ctrl.comm.start_server(&ctrl) {
            log::error!("Failed to start communications with service: {e}");
            return Err(anyhow!("Failed to start server thread: {e}"));
        }

        // Create a default USB device for the tests
        let usb = USBDevice {
            name: String::from("Kingston USB"),
            path: String::from("D:"),
            authorization: KeysasAuthorization::AllowedRead,
        };

        match ctrl.store.write() {
            Ok(mut store) => store.add_device(&usb),
            Err(e) => log::error!("Failed to get store lock: {e}"),
        }

        Ok(ctrl)
    }

    /// Called when a file notification has been received from the driver
    /// It adds the new file to the data store and notifies the view to update itself
    pub fn notify_file_change(&self, update: &FileUpdateMessage) {
        // Store the new file
        let file = FileAuth {
            device: String::from(&update.device),
            path: String::from(&update.path),
            authorization: update.authorization,
        };

        match self.store.write() {
            Ok(mut store) => {
                if let Err(e) = store.add_file(&file) {
                    println!("Failed to add file in store: {e}");
                    return;
                }
            }
            Err(e) => println!("Failed to get store lock: {e}"),
        }

        // Notify the GUI to update the view
        if let Err(e) = self
            .view
            .emit_all("file_update", String::from(&update.device))
        {
            println!("Failed to notify view of file changed: {e}");
        }
    }

    /// Return the list of files in the datastore
    pub fn get_file_list(&self, device_path: &str) -> Result<Vec<FileAuth>, anyhow::Error> {
        match self.store.read() {
            Ok(store) => store.get_files(device_path),
            Err(e) => return Err(anyhow!("Failed to get store lock: {e}")),
        }
    }

    /// Request a change of file authorization in the driver
    /// If it is successful it then change it in the datastore and updates the view
    pub fn request_file_auth_toggle(&self, device: &str, file: &str, curr_auth: bool) -> Result<(), anyhow::Error> {
        if let Err(e) = self.comm.send_msg(&FileUpdateMessage{
            device: device.to_string(),
            path: file.to_string(),
            authorization: curr_auth}) {
            return Err(anyhow!("Failed to send request to Keysas daemon: {e}"));
        }

        Ok(())
    }
}