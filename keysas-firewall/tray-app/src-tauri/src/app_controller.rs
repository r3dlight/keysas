// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Controller for the application

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

use crate::filter_store::{FileAuth, FilterStore, UsbDevice};
use crate::service_if::{FileUpdateMessage, FileAuthorization, ServiceInterface,
    UsbAuthorization, ServiceInterfaceBuilder, UsbUpdateMessage};

use anyhow::anyhow;
use std::sync::{Arc, RwLock};
use tauri::{AppHandle, Manager};

/// Application controller object, it contains handle to the application main services
pub struct AppController {
    pub store: RwLock<FilterStore>,
    view: AppHandle,
    comm: Box<dyn ServiceInterface + Send + Sync>,
}

impl AppController {
    /// Initialize the application controller
    /// It initialize
    ///     - the application data store
    ///     - the communication interface to the Keysas service
    ///     - store an handle to the view
    pub fn init(app_handle: AppHandle) -> Result<Arc<AppController>, anyhow::Error> {
        // Create the application controller
        let ctrl = Arc::new(AppController {
            store: RwLock::new(FilterStore::init_store()),
            view: app_handle,
            comm: ServiceInterfaceBuilder::build()?,
        });

        // Start the server thread
        if let Err(e) = ctrl.comm.start_server(&ctrl) {
            log::error!("Failed to start communications with service: {e}");
            return Err(anyhow!("Failed to start server thread: {e}"));
        }

        // Create a default USB device for the tests
        // let usb = USBDevice {
        //     name: String::from("Kingston USB"),
        //     path: String::from("D:"),
        //     authorization: UsbAuthorization::AllowRead,
        // };

        // match ctrl.store.write() {
        //     Ok(mut store) => store.add_device(&usb),
        //     Err(e) => log::error!("Failed to get store lock: {e}"),
        // }

        Ok(ctrl)
    }

    /// Called when a file notification has been received from the driver
    /// It adds the new file to the data store and notifies the view to update itself
    pub fn notify_file_change(&self, update: &FileUpdateMessage) {
        let mut id: [u16; 16] = Default::default();
        id.copy_from_slice(&update.id);

        // Store the new file
        let file = FileAuth {
            device: String::from(&update.device),
            id,
            path: String::from(&update.path),
            authorization: update.authorization.as_u8(),
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

    /// Called when a usb notification has been received from the driver
    pub fn notify_usb_change(&self, update: &UsbUpdateMessage) {
        // Store the new file
        let device = UsbDevice {
            name: String::from(&update.name),
            path: String::from(&update.path) ,
            authorization: update.authorization,
        };

        match self.store.write() {
            Ok(mut store) => store.add_device(&device),
            Err(e) => println!("Failed to get store lock: {e}"),
        }

        // Notify the GUI to update the view
        // if let Err(e) = self
        //     .view
        //     .emit_all("file_update", String::from(&update.device))
        // {
        //     println!("Failed to notify view of file changed: {e}");
        // }
    }

    /// Return the list of files in the datastore
    pub fn get_file_list(&self, device_path: &str) -> Result<Vec<FileAuth>, anyhow::Error> {
        match self.store.read() {
            Ok(store) => store.get_files(device_path),
            Err(e) => Err(anyhow!("Failed to get store lock: {e}")),
        }
    }

    /// Request a change of file authorization in the driver
    /// If it is successful it then change it in the datastore and updates the view
    pub fn request_file_auth_toggle(
        &self,
        device: &str,
        id: &[u16],
        path: &str,
        new_auth: FileAuthorization,
    ) -> Result<(), anyhow::Error> {
        let mut file_id: [u16; 16] = Default::default();
        file_id.copy_from_slice(id);

        if let Err(e) = self.comm.send_file_update(&FileUpdateMessage {
            device: device.to_string(),
            id: file_id,
            path: path.to_string(),
            authorization: new_auth,
        }) {
            println!("request_file_auth_toggle: File toggle failed: {e}");
            return Err(anyhow!("Failed to send request to Keysas daemon: {e}"));
        }

        Ok(())
    }
}
