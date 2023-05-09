// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Data store for Keysas filter application

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

use anyhow::anyhow;

#[derive(Debug, Clone)]
pub enum KeysasAuthorization {
    Blocked,
    AllowedRead,
    AllowedRwWarning,
    AllowedAll,
}

#[derive(Debug, Clone)]
pub struct FileAuth {
    pub path: String,
    pub authorization: KeysasAuthorization,
}

#[derive(Debug, Clone)]
pub struct USBDevice {
    pub name: String,
    pub path: String,
    pub authorization: KeysasAuthorization,
    pub files: Vec<FileAuth>,
}

#[derive(Debug, Clone)]
pub struct FilterStore {
    pub devices: Vec<USBDevice>,
}

impl FilterStore {
    pub fn init_store() -> FilterStore {
        FilterStore {
            devices: Vec::new(),
        }
    }

    pub fn add_device(&mut self, device: &USBDevice) {
        self.devices.push(device.clone());
    }

    pub fn remove_device(&mut self, device_name: &str) -> Result<(), anyhow::Error> {
        Ok(())
    }

    pub fn get_devices(&self) -> &[USBDevice] {
        &self.devices
    }

    pub fn set_device_auth(
        &mut self,
        device_name: &str,
        auth: KeysasAuthorization,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }

    pub fn add_file(&mut self, device_name: &str, file: &FileAuth) -> Result<(), anyhow::Error> {
        Ok(())
    }

    pub fn remove_file(&mut self, device_name: &str, file_name: &str) -> Result<(), anyhow::Error> {
        Ok(())
    }

    pub fn get_files(&self, device_name: &str) -> Result<&[FileAuth], anyhow::Error> {
        Err(anyhow!("Not implemented"))
    }

    pub fn set_file_auth(
        &mut self,
        device_name: &str,
        file_name: &str,
        auth: KeysasAuthorization,
    ) -> Result<(), anyhow::Error> {
        Ok(())
    }
}
