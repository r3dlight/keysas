// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Service controller

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

use libc::c_void;
use std::mem::size_of;
use std::path::PathBuf;
use std::path::{Component, Path};
use std::ffi::OsStr;
use std::sync::Arc;
use windows::core::PCSTR;
use windows::s;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Storage::FileSystem::{
    CreateFileA, ReadFile, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE,
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING,
};
use windows::Win32::System::Ioctl::VOLUME_DISK_EXTENTS;
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::UI::WindowsAndMessaging::*;
use anyhow::anyhow;

use keysas_lib::file_report::parse_report;
use crate::driver_interface::{WindowsDriverInterface, KeysasFilterOperation};
use crate::tray_interface;

/// Service controller object, it contains handles to the service communication interfaces and data
#[derive(Debug)]
pub struct ServiceController {
    driver_if: WindowsDriverInterface
}

impl ServiceController {
    /// Initialize the service controller
    pub fn init() -> Result<Arc<ServiceController>, anyhow::Error> {
        if !cfg!(windows) {
            log::error!("OS not supported");
            return Err(anyhow!("Failed to open driver interface: OS not supported"));
        }

        // TODO: load administration security policy

        // TODO: load local certificate store

        // Start the interface with the kernel driver
        let driver_interface = WindowsDriverInterface::open_driver_com()?;
    
        // Initialize the controller
        let ctrl = Arc::new(ServiceController {
            driver_if: driver_interface
        });

        driver_interface.start_driver_com(&ctrl)?;

        // Start the interface with the HMI
        if let Err(e) = tray_interface::init(&ctrl) {
            log::error!("Failed to start tray interface server: {e}");
            return Err(anyhow!("Failed to start tray interface server"));
        };
        
        Ok(ctrl)
    }

    /// Handle requests coming from the driver
    /// Return the status of the operation or an error
    /// 
    /// # Arguments
    /// 
    /// * 'operation' - Operation code
    /// * 'content' - Content of the request
    pub fn handle_driver_request(&self, operation: KeysasFilterOperation,
        content: &[u16]) -> Result<bool, anyhow::Error> {
        // Dispatch the request
        let result = match operation {
            KeysasFilterOperation::ScanFile | KeysasFilterOperation::UserAllowFile => {
                match self.authorize_file(operation, &content) {
                    Ok((result, true)) => {
                        // Send the authorization result to the tray interface
                        if let Err(e) = tray_interface::send_file_auth_status(
                                &content, result) {
                            println!("Failed to send file status to tray app {e}");
                        }
                        result
                    },
                    Ok((result, false)) => result,
                    Err(e) => {
                        println!("Failed to validate the file: {e}");
                        false
                    }
                }
            }
            KeysasFilterOperation::ScanUsb => false,
            KeysasFilterOperation::UserAllowAllUsb => false,
            KeysasFilterOperation::UserAllowUsbWithWarning => false,
        };

        Ok(result)
    }

    /// Handle a request coming from the HMI
    pub fn handle_tray_request(&self, req: &tray_interface::FileUpdateMessage) 
        -> Result<(), anyhow::Error> {
        // TODO - Check that the request is conforme to the security policy

        // Send the request to the driver
        let msg = match serde_json::to_string(req) {
            Ok(m) => m,
            Err(e) => return Err(anyhow!("Failed to serialize request: {e}"))
        };

        if let Err(e) = self.driver_if.send_msg(&msg) {
            println!("Failed to pass tray request to driver {e}");
            return Err(anyhow!("Failed to pass tray request to driver {e}"));
        }
        
        Ok(())
    }

    /// Check a USB device to allow it not
    /// Return Ok(true) or Ok(false) according to the authorization
    /// 
    /// # Arguments
    /// 
    /// * 'content' - Content of the request from the driver
    fn authorize_usb(&self, content: &[u16]) -> Result<bool, anyhow::Error> {
        println!("Received USB scan request: {:?}", content);
        let mut buffer: [u8; 4096] = [0; 4096];
        let mut byte_read: u32 = 0;

        // Open the device on the first sector
        let device = unsafe {
            match CreateFileA(
                s!("\\\\.\\D:"),
                1179785u32,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            ) {
                Ok(d) => d,
                Err(_) => {
                    println!("Failed to open device");
                    let err = GetLastError();
                    println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
                    return Err(anyhow!("Failed to open device"));
                }
            }
        };

        if device.is_invalid() {
            println!("Invalid device handle");
            return Err(anyhow!("Invalid device handle"));
        }

        let mut vde = VOLUME_DISK_EXTENTS::default();
        let mut dw: u32 = 0;
        match unsafe {
            DeviceIoControl(
                device,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                None,
                0,
                Some(&mut vde as *mut _ as *mut c_void),
                u32::try_from(size_of::<VOLUME_DISK_EXTENTS>())?,
                Some(&mut dw),
                None,
            ).as_bool()
        } {
            true => (),
            false => {
                println!("Failed to query device");
                return Err(anyhow!("Failed to query device"));

            }
        }

        let mut drive_path = String::from("\\\\.\\PhysicalDrive");
        drive_path.push_str(&vde.Extents[0].DiskNumber.to_string());

        println!("Physical Drive path: {:?}", drive_path);

        let drive_str = PCSTR::from_raw(drive_path.as_ptr() as *const u8);
        unsafe {
            println!("Physical Drive path windows: {:?}", drive_str.to_string()?);
        }

        let handle_usb = unsafe {
            match CreateFileA(
                drive_str,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                None,
            ) {
                Ok(d) => d,
                Err(_) => {
                    println!("Failed to open usb");
                    let err = GetLastError();
                    println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
                    return Err(anyhow!("Failed to open usb"));
                }
            }
        };

        if handle_usb.is_invalid() {
            println!("Invalid device usb handle");
            return Err(anyhow!("Invalid device usb handle"));
        }

        // Move the file pointer after the MBR table (512B)
        // and read the signature content
        let read = unsafe {
            //SetFilePointer(device, 512, None, FILE_BEGIN);
            ReadFile(
                handle_usb,
                Some(buffer.as_mut_ptr() as *mut c_void),
                4096,
                Some(&mut byte_read),
                None,
            )
        };

        if read.as_bool() {
            println!("Device content: {:?}", buffer);
        } else {
            println!("Failed to read device content");
            unsafe {
                let err = GetLastError();
                println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
            }
        }

        Ok(true)
    }

    /// Decide to authorize a file
    /// Start by whitelisting file that belongs to Windows and remove directories
    /// Then try to validate it with a station report
    /// Finaly if it fails ask the user to validate it manualy
    /// 
    /// USB_op will be used to apply a device wide filter policy
    /// 
    /// Returns a tuple containing
    ///     - if the file is authorized or not
    ///     - if a notification must be sent to the user or not
    /// 
    /// # Arguments
    /// 
    /// * 'usb_op' - Device wide filtering policy
    /// * 'content' - Content of the driver request, it contains the path to the file
    fn authorize_file(&self, _usb_op: KeysasFilterOperation, content: &[u16]) 
        -> Result<(bool, bool), anyhow::Error> {
        // Extract content of the request
        // The first 32 bytes are the File ID
        let file_id = &content[1..16];
        // The next part contains the file name
        let file_name = match String::from_utf16(&content[17..]) {
            Ok(name) => name,
            Err(_) => {
                println!("Failed to convert request to string");
                return Ok((false, false));
            }
        };

        let file_path = Path::new(file_name.trim_matches(char::from(0)));

        println!("Received file ID: {:?} with name : {:?}", file_id, file_path);

        // Try to get the parent directory
        let mut components = file_path.components();

        // First component is the Root Directory
        // If the second directory is "System Volume Information" then it is internal to windows, skip it
        loop {
            let c = components.next();
            if c.is_none() || c == Some(Component::RootDir) {
                break;
            }
        }

        if components.next() == Some(Component::Normal(OsStr::new("System Volume Information"))) {
            return Ok((true, false));
        }

        // Skip the directories
        if file_path.metadata()?.is_dir() {
            return Ok((true, false));
        }

        // Try to validate the file from the station report
        match self.validate_file(file_path) {
            Ok(true) => {
                return Ok((true, true));
            }
            _ => {
                println!("File not validated by station");
            }
        }

        // If the validation fails, ask the user authorization
        self.user_authorize_file(file_path).map(|r| (r, true))
    }

    /// Check a file
    ///  - If it is a normal file, try to find the corresponding station report
    ///     - If there is none, return False
    ///     - If there is one, validate both
    ///  - If the file is a station report, try to find the corresponding file
    ///     - If there is none, try to validate the report alone. There must be no file digest referenced in it
    ///     - If there is one, validate both
    /// 
    /// # Arguments
    /// 
    /// * 'path' - Path to the file
    fn validate_file(&self, path: &Path) -> Result<bool, anyhow::Error> {
        // Test if the file is a station report
        if Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("krp"))
        {
            // Try to find the corresponding file
            let mut file_path = path.to_path_buf();
            // file_path.file_name should not be None at this point
            file_path.set_extension("");

            match file_path.is_file() {
                true => {
                    // If it exists, validate both
                    match parse_report(Path::new(path), Some(&file_path), None, None) {
                        Ok(_) => return Ok(true),
                        Err(e) => {
                            println!("Failed to parse report: {e}");
                            return Ok(false);
                        }
                    }
                },
                false => {
                    // If no corresponding file validate it alone
                    match parse_report(Path::new(path), None, None, None) {
                        Ok(_) => return Ok(true),
                        Err(e) => {
                            println!("Failed to parse report: {e}");
                            return Ok(false);
                        }
                    }
                }
            }
        }

        // If not try to find the corresponding report
        // It should be in the same directory with the same name + '.krp'
        let mut path_report = PathBuf::from(path);
        match path_report.extension() {
            Some(ext) => {
                let mut ext = ext.to_os_string();
                ext.push(".krp");
                path_report.set_extension(ext);
            },
            _ => {
                path_report.set_extension(".krp");
            }
        }
        match path_report.is_file() {
            true => {
                // If a corresponding report is found then validate both the file and the report
                if let Err(e) = parse_report(path_report.as_path(), Some(path), None, None) {
                    println!("Failed to parse file and report: {e}");
                    return Ok(false);
                }
                Ok(true)
            }
            false => {
                // There is no corresponding report for validating the file
                println!("No report found at {:?}", path_report);
                Ok(false)
            }
        }
    }

    /// Spawn a dialog box to ask the user to validate a file or not
    /// Return Ok(true) or Ok(false) accordingly
    /// 
    /// # Arguments
    /// 
    /// * 'path' - Path to the file
    fn user_authorize_file(&self, path: &Path) -> Result<bool, anyhow::Error> {
        // Find authorization status for the file
        let auth_request = format!("Allow file: {:?}", path.as_os_str());
        let (auth_request_ptr, _, _) = auth_request.into_raw_parts();

        let authorization_status = unsafe {
            MessageBoxA(
                None,
                PCSTR::from_raw(auth_request_ptr),
                s!("Keysas USB Filter"),
                MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL,
            )
        };

        match authorization_status {
            IDYES => {
                Ok(true)
            }
            IDNO => {
                Ok(false)
            }
            _ => {
                Err(anyhow!(format!(
                    "Unknown Authorization: {:?}",
                    authorization_status
                )))
            }
        }
    }
}