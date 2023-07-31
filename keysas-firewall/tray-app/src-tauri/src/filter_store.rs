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

use serde::Serialize;
use crate::service_if::KeysasAuthorization;

#[derive(Debug, Clone, Serialize)]
pub struct FileAuth {
    pub device: String,
    pub id: [u16; 16],
    pub path: String,
    pub authorization: u8,
}

#[derive(Debug, Clone)]
pub struct USBDevice {
    pub name: String,
    pub path: String,
    pub authorization: KeysasAuthorization,
}

#[derive(Debug, Clone)]
pub struct FilterStore {
    pub devices: Vec<USBDevice>,
    pub files: Vec<FileAuth>,
}

impl FilterStore {
    pub fn init_store() -> FilterStore {
        FilterStore {
            devices: Vec::new(),
            files: Vec::new(),
        }
    }

    pub fn add_device(&mut self, device: &USBDevice) {
        self.devices.push(device.clone());
    }

    pub fn remove_device(&mut self, _device_name: &str) -> Result<(), anyhow::Error> {
        todo!()
    }

    pub fn get_devices(&self) -> &[USBDevice] {
        &self.devices
    }

    pub fn get_device(&self, device_path: &str) -> Option<&USBDevice> {
        self.devices.iter().find(|&d| d.path.eq(device_path))
    }

    pub fn get_device_mut(&mut self, device_path: &str) -> Option<&mut USBDevice> {
        self.devices.iter_mut().find(|d| d.path.eq(device_path))
    }

    pub fn set_device_auth(
        &mut self,
        _device_name: &str,
        _auth: KeysasAuthorization,
    ) -> Result<(), anyhow::Error> {
        todo!()
    }

    pub fn add_file(&mut self, file: &FileAuth) -> Result<(), anyhow::Error> {
        self.files.push(file.clone());
        Ok(())
    }

    pub fn remove_file(
        &mut self,
        _device_name: &str,
        _file_name: &str,
    ) -> Result<(), anyhow::Error> {
        todo!()
    }

    pub fn get_files(&self, device_path: &str) -> Result<Vec<FileAuth>, anyhow::Error> {
        let files: Vec<FileAuth> = self
            .files
            .iter()
            .filter_map(|f| match f.device.eq(device_path) {
                true => Some(f.clone()),
                false => None,
            })
            .collect();
        Ok(files)
    }

    pub fn set_file_auth(
        &mut self,
        _device_name: &str,
        _file_name: &str,
        _auth: KeysasAuthorization,
    ) -> Result<(), anyhow::Error> {
        todo!()
    }
}
