// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! USB monitor implementation for Windows

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

use std::{
    sync::{Arc, Mutex},
    ffi::OsString
};
use anyhow::anyhow;
use log::*;

use crate::controller::{ServiceController, UsbDevice};
use crate::usb_monitor::UsbMonitor;

pub struct WindowsUsbMonitor {}

impl WindowsUsbMonitor {
    pub fn init() -> Result<WindowsUsbMonitor, anyhow::Error> {
        Ok(Self {})
    }
}

impl UsbMonitor for WindowsUsbMonitor {
    fn start(&self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error> {
        // For now register a fake Usb device to allow file classification
        let fake = UsbDevice {
            device_id: OsString::from("\\\\.\\PhysicalDrive1"),
            mnt_point: Some(OsString::from("\\\\.\\D:")),
            vendor: OsString::from("Kingston"),
            model: OsString::from("Test"),
            revision: OsString::from("1"),
            serial: OsString::from("Test")
        };

        let mut ctrl_hdl = ctrl.lock().unwrap();

        match ctrl_hdl.authorize_usb(&fake, None) {
            Ok(decision) => {
                info!("Authorization granted: {decision}");
            },
            Err(e) => {
                error!("Failed to validate Usb device: {e}");
            }
        }

        Ok(())
        

        // let mut buffer: [u8; 4096] = [0; 4096];
        // let mut byte_read: u32 = 0;

        // // Open the device on the first sector
        // let device = unsafe {
        //     match CreateFileA(
        //         s!("\\\\.\\D:"),
        //         1179785u32,
        //         FILE_SHARE_READ | FILE_SHARE_WRITE,
        //         None,
        //         OPEN_EXISTING,
        //         FILE_FLAG_BACKUP_SEMANTICS,
        //         None,
        //     ) {
        //         Ok(d) => d,
        //         Err(_) => {
        //             println!("Failed to open device");
        //             let err = GetLastError();
        //             println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
        //             return Err(anyhow!("Failed to open device"));
        //         }
        //     }
        // };

        // if device.is_invalid() {
        //     println!("Invalid device handle");
        //     return Err(anyhow!("Invalid device handle"));
        // }

        // let mut vde = VOLUME_DISK_EXTENTS::default();
        // let mut dw: u32 = 0;
        // match unsafe {
        //     DeviceIoControl(
        //         device,
        //         IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        //         None,
        //         0,
        //         Some(&mut vde as *mut _ as *mut c_void),
        //         u32::try_from(size_of::<VOLUME_DISK_EXTENTS>())?,
        //         Some(&mut dw),
        //         None,
        //     ).as_bool()
        // } {
        //     true => (),
        //     false => {
        //         println!("Failed to query device");
        //         return Err(anyhow!("Failed to query device"));

        //     }
        // }

        // let mut drive_path = String::from("\\\\.\\PhysicalDrive");
        // drive_path.push_str(&vde.Extents[0].DiskNumber.to_string());

        // println!("Physical Drive path: {:?}", drive_path);

        // let drive_str = PCSTR::from_raw(drive_path.as_ptr() as *const u8);
        // unsafe {
        //     println!("Physical Drive path windows: {:?}", drive_str.to_string()?);
        // }

        // let handle_usb = unsafe {
        //     match CreateFileA(
        //         drive_str,
        //         0,
        //         FILE_SHARE_READ | FILE_SHARE_WRITE,
        //         None,
        //         OPEN_EXISTING,
        //         FILE_FLAG_BACKUP_SEMANTICS,
        //         None,
        //     ) {
        //         Ok(d) => d,
        //         Err(_) => {
        //             println!("Failed to open usb");
        //             let err = GetLastError();
        //             println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
        //             return Err(anyhow!("Failed to open usb"));
        //         }
        //     }
        // };

        // if handle_usb.is_invalid() {
        //     println!("Invalid device usb handle");
        //     return Err(anyhow!("Invalid device usb handle"));
        // }

        // // Move the file pointer after the MBR table (512B)
        // // and read the signature content
        // let read = unsafe {
        //     //SetFilePointer(device, 512, None, FILE_BEGIN);
        //     ReadFile(
        //         handle_usb,
        //         Some(buffer.as_mut_ptr() as *mut c_void),
        //         4096,
        //         Some(&mut byte_read),
        //         None,
        //     )
        // };

        // if read.as_bool() {
        //     println!("Device content: {:?}", buffer);
        // } else {
        //     println!("Failed to read device content");
        //     unsafe {
        //         let err = GetLastError();
        //         println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
        //     }
        // }
    }

    /// Update a usb policy
    ///
    /// # Arguments
    ///
    /// `update` - Information on the usb key and the new authorization status
    fn update_usb_auth(&self, _update: &UsbDevice) -> Result<(), anyhow::Error> {
        Err(anyhow!("USB authorization update not implemented"))
    }

    /// Stop the monitor
    fn stop(self: Box<Self>) {
    }
}
