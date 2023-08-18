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

use std::path::PathBuf;
use std::path::{Component, Path};
use std::ffi::OsStr;
use std::sync::Arc;
use std::fs;
use windows::core::PCSTR;
use windows::core::s;
use windows::Win32::UI::WindowsAndMessaging::*;
use anyhow::anyhow;
use serde::Deserialize;
use x509_cert::Certificate;
use x509_cert::der::DecodePem;

use keysas_lib::file_report::parse_report;
use crate::driver_interface::{WindowsDriverInterface, KeysasFilterOperation, KeysasAuthorization};
use crate::tray_interface;
use crate::Config;

#[derive(Debug, Deserialize, Clone, Copy)]
struct SecurityPolicy {
    disable_unsigned_usb: bool,
    allow_user_usb_authorization: bool,
    allow_user_file_read: bool,
    allow_user_file_write: bool,
}

impl Default for SecurityPolicy {
    fn default() -> Self {
        Self {
            disable_unsigned_usb: false,
            allow_user_usb_authorization: false,
            allow_user_file_read: false,
            allow_user_file_write: false,
        }
    }
}

/// Service controller object, it contains handles to the service communication interfaces and data
#[derive(Debug, Clone)]
pub struct ServiceController {
    driver_if: WindowsDriverInterface,
    policy: SecurityPolicy,
    ca_cert_cl: Certificate,
    ca_cert_pq: Certificate
}

impl ServiceController {
    /// Initialize the service controller
    pub fn init(config: &Config) -> Result<Arc<ServiceController>, anyhow::Error> {
        if !cfg!(windows) {
            log::error!("OS not supported");
            return Err(anyhow!("Failed to open driver interface: OS not supported"));
        }

        // Load administration security policy
        let config_toml = match fs::read_to_string(&config.config) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Failed to read configuration file {e}");
                return Err(anyhow!("Failed to open driver interface: Failed to read configuration file {e}"));
            }
        };

        let policy: SecurityPolicy = match toml::from_str(&config_toml) {
            Ok(p) => p,
            Err(e) =>  {
                log::error!("Failed to parse configuration file {e}");
                return Err(anyhow!("Failed to open driver interface: Failed to parse configuration file {e}"));
            }
        };

        // Load local certificates for the CA
        let cl_cert_pem = fs::read_to_string(&config.ca_cert_cl)?;
        let ca_cert_cl = Certificate::from_pem(cl_cert_pem)?;

        let pq_cert_pem = fs::read_to_string(&config.ca_cert_pq)?;
        let ca_cert_pq = Certificate::from_pem(pq_cert_pem)?;


        // Start the interface with the kernel driver
        let driver_if = WindowsDriverInterface::open_driver_com()?;
    
        // Initialize the controller
        let ctrl = Arc::new(ServiceController {
            driver_if,
            policy,
            ca_cert_cl,
            ca_cert_pq
        });

        driver_if.start_driver_com(&ctrl)?;

        // Start the interface with the HMI
        if let Err(e) = tray_interface::init(&ctrl) {
            log::error!("Failed to start tray interface server: {e}");
            return Err(anyhow!("Failed to start tray interface server"));
        };
        
        Ok(ctrl)
    }

    /// Handle requests coming from the driver
    /// Return the authorization state for the USB device or the file, or an error
    /// 
    /// # Arguments
    /// 
    /// * 'operation' - Operation code
    /// * 'content' - Content of the request
    pub fn handle_driver_request(&self, operation: KeysasFilterOperation,
        content: &[u16]) -> Result<KeysasAuthorization, anyhow::Error> {
        // Dispatch the request
        let result = match operation {
            KeysasFilterOperation::ScanFile => {
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
                        KeysasAuthorization::AuthBlock
                    }
                }
            }
            KeysasFilterOperation::ScanUsb => KeysasAuthorization::AuthAllowAll, // For now, allow all
        };

        Ok(result)
    }

    /// Handle a request coming from the HMI
    pub fn handle_tray_request(&self, req: &tray_interface::FileUpdateMessage) 
        -> Result<(), anyhow::Error> {
        // Check that the request is conforme to the security policy
        if (KeysasAuthorization::AuthAllowRead == req.authorization) 
            && !self.policy.allow_user_file_read {
            println!("Authorization change not allowed");
            return Err(anyhow!("Authorization change not allowed"));
        }

        if (KeysasAuthorization::AuthAllowAll == req.authorization) 
            && (!self.policy.allow_user_file_read
                || !self.policy.allow_user_file_write) {
            println!("Authorization change not allowed");
            return Err(anyhow!("Authorization change not allowed"));
        }

        // Create the request for the driver
        // The format is :
        //   - FileID: 32 bytes
        //   - New authorization: 1 byte
        let mut request: [u8; 33] = [0; 33];
        let mut index = 0;

        for db in req.id {
            let bytes = db.to_ne_bytes();
            request[index] = bytes[0];
            request[index+1] = bytes[1];
            index += 2;
        }
        request[32] = req.authorization.as_u8();

        // Send the request to the driver
        if let Err(e) = self.driver_if.send_msg(&request) {
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
    fn authorize_usb(&self, _content: &[u16]) -> Result<bool, anyhow::Error> {
        return Ok(true);
        /*
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
                    if let Err(e) = GetLastError() {
                        println!("Error: {:?}", e.message().to_string_lossy());
                    }
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
        unsafe {
            if let Err(e) = DeviceIoControl(
                device,
                IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                None,
                0,
                Some(&mut vde as *mut _ as *mut c_void),
                u32::try_from(size_of::<VOLUME_DISK_EXTENTS>())?,
                Some(&mut dw),
                None,
            ) {
                println!("Error: {:?}", e.message().to_string_lossy());
                return Err(anyhow!("Failed to open device"));
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
                    if let Err(e) = GetLastError() {
                        println!("Error: {:?}", e.message().to_string_lossy());
                    }
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
                Some(&mut buffer),
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
        */
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
        -> Result<(KeysasAuthorization, bool), anyhow::Error> {
        // Extract content of the request
        // The first 32 bytes are the File ID
        let file_id = &content[1..16];
        // The next part contains the file name
        let file_name = match String::from_utf16(&content[17..]) {
            Ok(name) => name,
            Err(_) => {
                println!("Failed to convert request to string");
                return Ok((KeysasAuthorization::AuthBlock, false));
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
            return Ok((KeysasAuthorization::AuthAllowAll, false));
        }

        // Skip the directories
        if file_path.metadata()?.is_dir() {
            return Ok((KeysasAuthorization::AuthAllowAll, false));
        }

        // Try to validate the file from the station report
        match self.validate_file(file_path) {
            Ok(true) => {
                return Ok((KeysasAuthorization::AuthAllowRead, true));
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
                    match parse_report(Path::new(path), Some(&file_path), 
                                        Some(&self.ca_cert_cl),
                                        Some(&self.ca_cert_pq)) {
                        Ok(_) => return Ok(true),
                        Err(e) => {
                            println!("Failed to parse report: {e}");
                            return Ok(false);
                        }
                    }
                },
                false => {
                    // If no corresponding file validate it alone
                    match parse_report(Path::new(path), None,
                                        Some(&self.ca_cert_cl),
                                        Some(&self.ca_cert_pq)) {
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
                if let Err(e) = parse_report(path_report.as_path(), Some(path),
                                                Some(&self.ca_cert_cl),
                                                Some(&self.ca_cert_pq)) {
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
    fn user_authorize_file(&self, path: &Path) -> Result<KeysasAuthorization, anyhow::Error> {
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
                Ok(KeysasAuthorization::AuthAllowRead)
            }
            IDNO => {
                Ok(KeysasAuthorization::AuthBlock)
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