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
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]

use anyhow::anyhow;
use libc::c_void;
use serde::Deserialize;
use std::ffi::OsStr;
use std::fs;
use std::mem::size_of;
use std::path::PathBuf;
use std::path::{Component, Path};
use std::sync::Arc;
use x509_cert::der::DecodePem;
use x509_cert::Certificate;

//#[cfg(target_os = "windows")]
//{
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

use registry::{Data, Hive, Security};
//}

use crate::driver_interface::{KeysasAuthorization, KeysasFilterOperation, WindowsDriverInterface};
use crate::tray_interface;
use crate::Config;
use keysas_lib::file_report::parse_report;

#[derive(Debug, Deserialize, Clone, Copy, Default)]
struct SecurityPolicy {
    disable_unsigned_usb: bool,
    allow_user_usb_authorization: bool,
    allow_user_file_read: bool,
    allow_user_file_write: bool,
}

/// Service controller object, it contains handles to the service communication interfaces and data
#[derive(Debug, Clone)]
pub struct ServiceController {
    driver_if: WindowsDriverInterface,
    policy: SecurityPolicy,
    ca_cert_cl: Certificate,
    ca_cert_pq: Certificate,
}

#[cfg(target_os = "windows")]
fn load_security_policy(_config: &Config) -> Result<SecurityPolicy, anyhow::Error> {
    let regkey = match Hive::LocalMachine.open(
        r"SYSTEM\CurrentControlSet\Services\Keysas Service\config",
        Security::Read,
    ) {
        Ok(r) => r,
        Err(e) => {
            return Err(anyhow!(
                "Failed to open driver interface: Failed to open registry key {e}"
            ));
        }
    };

    let policy = SecurityPolicy {
        disable_unsigned_usb: matches!(regkey.value("DisableUnsignedUsb"), Ok(Data::U32(1))),
        allow_user_usb_authorization: matches!(
            regkey.value("AllowUserUsbAuthorization"),
            Ok(Data::U32(1))
        ),
        allow_user_file_read: matches!(regkey.value("AllowUserFileRead"), Ok(Data::U32(1))),
        allow_user_file_write: matches!(regkey.value("AllowUserFileWrite"), Ok(Data::U32(1))),
    };

    Ok(policy)
}

#[cfg(target_os = "linux")]
fn load_security_policy(config: &Config) -> Result<SecurityPolicy, anyhow::Error> {
    // Load administration security policy
    let mut config_path = std::env::current_dir()?;
    config_path.push(&config.config);
    // &config.config
    let config_toml = match fs::read_to_string(config_path) {
        Ok(s) => s,
        Err(e) => {
            let cur_env = std::env::current_exe().unwrap();
            let exe_path = cur_env.to_str().unwrap();
            return Err(anyhow!("Failed to open driver interface: Failed to read configuration file {e} from {exe_path}"));
        }
    };

    let policy: SecurityPolicy = match toml::from_str(&config_toml) {
        Ok(p) => p,
        Err(e) => {
            return Err(anyhow!(
                "Failed to open driver interface: Failed to parse configuration file {e}"
            ));
        }
    };

    Ok(policy)
}

#[cfg(target_os = "windows")]
fn load_usb_cert(_config: &Config) -> Result<(Certificate, Certificate), anyhow::Error> {
    let regkey = match Hive::LocalMachine.open(
        r"SYSTEM\CurrentControlSet\Services\Keysas Service\config",
        Security::Read,
    ) {
        Ok(r) => r,
        Err(e) => {
            return Err(anyhow!(
                "Failed to open driver interface: Failed to open registry key {e}"
            ));
        }
    };

    let cl_path = match regkey.value("UsbCaClCert") {
        Ok(Data::String(s)) => s.to_string_lossy(),
        _ => {
            return Err(anyhow!("Failed to get value to path to CL certificate"));
        }
    };

    let pq_path = match regkey.value("UsbCaPqCert") {
        Ok(Data::String(s)) => s.to_string_lossy(),
        _ => {
            return Err(anyhow!("Failed to get value to path to CL certificate"));
        }
    };

    let cl_cert_pem = fs::read_to_string(cl_path)?;
    let ca_cert_cl = Certificate::from_pem(cl_cert_pem)?;

    let pq_cert_pem = fs::read_to_string(pq_path)?;
    let ca_cert_pq = Certificate::from_pem(pq_cert_pem)?;

    Ok((ca_cert_cl, ca_cert_pq))
}

#[cfg(target_os = "linux")]
fn load_usb_cert(config: &Config) -> Result<(Certificate, Certificate), anyhow::Error> {
    let cl_cert_pem = fs::read_to_string(&config.ca_cert_cl)?;
    let ca_cert_cl = Certificate::from_pem(cl_cert_pem)?;

    let pq_cert_pem = fs::read_to_string(&config.ca_cert_pq)?;
    let ca_cert_pq = Certificate::from_pem(pq_cert_pem)?;

    Ok((ca_cert_cl, ca_cert_pq))
}

impl ServiceController {
    /// Initialize the service controller
    pub fn init(config: &Config) -> Result<Arc<ServiceController>, anyhow::Error> {
        if !cfg!(windows) {
            log::error!("OS not supported");
            return Err(anyhow!("Failed to open driver interface: OS not supported"));
        }

        let policy = match load_security_policy(config) {
            Ok(p) => p,
            Err(e) => {
                log::error!("Failed to load security policy {e}");
                return Err(anyhow!(
                    "Failed to open driver interface: Failed to load security policy {e}"
                ));
            }
        };
        log::info!("Policy loaded");

        // Load local certificates for the CA
        let (ca_cert_cl, ca_cert_pq) = match load_usb_cert(config) {
            Ok(c) => c,
            Err(e) => {
                log::error!("Failed to load certificates {e}");
                return Err(anyhow!(
                    "Failed to open driver interface: Failed to load certificates {e}"
                ));
            }
        };

        // Start the interface with the kernel driver
        let driver_if = WindowsDriverInterface::open_driver_com()?;

        // Initialize the controller
        let ctrl = Arc::new(ServiceController {
            driver_if,
            policy,
            ca_cert_cl,
            ca_cert_pq,
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
    pub fn handle_driver_request(
        &self,
        operation: KeysasFilterOperation,
        content: &[u16],
    ) -> Result<KeysasAuthorization, anyhow::Error> {
        // Dispatch the request
        let result = match operation {
            KeysasFilterOperation::ScanFile => {
                match self.authorize_file(operation, content) {
                    Ok((result, true)) => {
                        // Send the authorization result to the tray interface
                        if let Err(e) = tray_interface::send_file_auth_status(content, result) {
                            println!("Failed to send file status to tray app {e}");
                        }
                        result
                    }
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
    pub fn handle_tray_request(
        &self,
        req: &tray_interface::FileUpdateMessage,
    ) -> Result<(), anyhow::Error> {
        // Check that the request is conforme to the security policy
        if (KeysasAuthorization::AuthAllowRead == req.authorization)
            && !self.policy.allow_user_file_read
        {
            println!("Authorization change not allowed");
            return Err(anyhow!("Authorization change not allowed"));
        }

        if (KeysasAuthorization::AuthAllowAll == req.authorization)
            && (!self.policy.allow_user_file_read || !self.policy.allow_user_file_write)
        {
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
            request[index + 1] = bytes[1];
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
            )
            .as_bool()
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

        let drive_str = PCSTR::from_raw(drive_path.as_ptr());
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
    fn authorize_file(
        &self,
        _usb_op: KeysasFilterOperation,
        content: &[u16],
    ) -> Result<(KeysasAuthorization, bool), anyhow::Error> {
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

        println!(
            "Received file ID: {:?} with name : {:?}",
            file_id, file_path
        );

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
                    match parse_report(
                        Path::new(path),
                        Some(&file_path),
                        Some(&self.ca_cert_cl),
                        Some(&self.ca_cert_pq),
                    ) {
                        Ok(_) => return Ok(true),
                        Err(e) => {
                            println!("Failed to parse report: {e}");
                            return Ok(false);
                        }
                    }
                }
                false => {
                    // If no corresponding file validate it alone
                    match parse_report(
                        Path::new(path),
                        None,
                        Some(&self.ca_cert_cl),
                        Some(&self.ca_cert_pq),
                    ) {
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
            }
            _ => {
                path_report.set_extension(".krp");
            }
        }
        match path_report.is_file() {
            true => {
                // If a corresponding report is found then validate both the file and the report
                if let Err(e) = parse_report(
                    path_report.as_path(),
                    Some(path),
                    Some(&self.ca_cert_cl),
                    Some(&self.ca_cert_pq),
                ) {
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
            IDYES => Ok(KeysasAuthorization::AuthAllowRead),
            IDNO => Ok(KeysasAuthorization::AuthBlock),
            _ => Err(anyhow!(format!(
                "Unknown Authorization: {:?}",
                authorization_status
            ))),
        }
    }
}
