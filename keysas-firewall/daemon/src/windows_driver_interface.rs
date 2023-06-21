// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! KeysasDriverInterface is a generic interface to send and receive messages
//! to the firewall driver in kernel space.
//! The interface must be specialized for Linux or Windows

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

use anyhow::anyhow;
use libc::c_void;
use std::mem::size_of;
use std::path::PathBuf;
use std::path::{Component, Path};
use std::thread;
use std::ffi::OsStr;
use widestring::U16CString;
use windows::core::{PCSTR, PCWSTR};
use windows::s;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, BOOLEAN, HANDLE, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, ReadFile, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE,
    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, OPEN_EXISTING,
};
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterGetMessage, FilterReplyMessage, FILTER_MESSAGE_HEADER,
    FILTER_REPLY_HEADER,
};
use windows::Win32::System::Ioctl::VOLUME_DISK_EXTENTS;
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::UI::WindowsAndMessaging::*;

use keysas_lib::file_report::parse_report;

/// Operation code for the request to userland
#[derive(Debug)]
enum KeysasFilterOperation {
    /// Validate the signature of the file and the report
    ScanFile = 0,
    /// Ask user to allow the file
    UserAllowFile,
    /// Ask to validate the USB drive signature
    ScanUsb,
    /// Ask user to allow complete access the USB drive
    UserAllowAllUsb,
    /// Ask user to allow access to USB drive with warning on file opening
    UserAllowUsbWithWarning,
}

/// Format of a request from the driver to the service scanner
#[derive(Debug)]
#[repr(C)]
struct DriverRequest {
    /// Header of the request managed by Windows
    header: FILTER_MESSAGE_HEADER,
    /// Operation code defined in [KeysasFilterOperation]
    operation: KeysasFilterOperation,
    /// Buffer with the content of the operation
    content: [u16; 1024],
}

/// Format of a reply to the driver
#[derive(Debug)]
#[repr(C)]
struct UserReply {
    /// Header of the message, managed by Windows
    header: FILTER_REPLY_HEADER,
    /// Result of the request
    result: BOOLEAN,
}

/// Handle to the driver interface
#[derive(Debug, Copy, Clone)]
pub struct WindowsDriverInterface {
    /// Handle to the communication port
    handle: HANDLE,
}

/// Name of the communication port with the driver
const DRIVER_COM_PORT: &str = "\\KeysasPort";

impl WindowsDriverInterface {
    /// Initialize the interface to the Windows driver
    /// The connection is made with the name in DRIVER_COM_PORT
    pub fn open_driver_com() -> Result<WindowsDriverInterface, anyhow::Error> {
        // Open communication canal with the driver
        let com_port_name = U16CString::from_str(DRIVER_COM_PORT).unwrap().into_raw();

        let handle = unsafe {
            match FilterConnectCommunicationPort(PCWSTR(com_port_name), 0, None, 0, None) {
                Ok(h) => h,
                Err(e) => {
                    log::error!("Connection to minifilter failed: {e}");
                    return Err(anyhow!("Connection to minifilter failed: {e}"));
                }
            }
        };

        Ok(Self { handle })
    }

    /// Start listening to the drivers' requests and register a callback to handle them
    ///
    /// # Arguments
    ///
    /// * `cb` - Callback to handle the driver requests
    pub fn start_driver_com(&self, _cb: fn() -> ()) -> Result<(), anyhow::Error> {
        let handle = self.handle;
        thread::spawn(move || -> Result<(), anyhow::Error> {
            let request_size = u32::try_from(size_of::<DriverRequest>())?;
            let reply_size = u32::try_from(size_of::<FILTER_REPLY_HEADER>())?
                + u32::try_from(size_of::<BOOLEAN>())?;

            loop {
                // Wait for a request from the driver
                let mut request = DriverRequest {
                    header: FILTER_MESSAGE_HEADER::default(),
                    operation: KeysasFilterOperation::ScanFile,
                    content: [0; 1024],
                };

                unsafe {
                    if FilterGetMessage(handle, &mut request.header, request_size, None).is_err()
                    {
                        println!("Failed to get message from driver");
                        continue;
                    }
                }

                // Convert the request to Rust String
                let content = match String::from_utf16(&request.content) {
                    Ok(c) => c,
                    Err(_) => {
                        println!("Failed to convert request to string");
                        // Send error response to driver
                        let reply = UserReply {
                            header: FILTER_REPLY_HEADER {
                                MessageId: request.header.MessageId,
                                Status: STATUS_UNSUCCESSFUL,
                            },
                            result: BOOLEAN::from(false),
                        };
                        unsafe {
                            if FilterReplyMessage(handle, &reply.header, reply_size).is_err() {
                                println!("Failed to send response to driver");
                            }
                        }
                        continue;
                    }
                };

                // Dispatch the request
                let result = match request.operation {
                    KeysasFilterOperation::ScanFile | KeysasFilterOperation::UserAllowFile => {
                        matches!(authorize_file(request.operation, &content), Ok(true))
                    }
                    KeysasFilterOperation::ScanUsb => true /*match authorize_usb(&content) {
                        Ok(true) => true,
                        _ => false,
                    }*/,
                    KeysasFilterOperation::UserAllowAllUsb => true,
                    KeysasFilterOperation::UserAllowUsbWithWarning => true,
                };

                // Prepare the response and send it
                let reply = UserReply {
                    header: FILTER_REPLY_HEADER {
                        MessageId: request.header.MessageId,
                        Status: STATUS_SUCCESS,
                    },
                    result: BOOLEAN::from(result),
                };

                unsafe {
                    if FilterReplyMessage(handle, &reply.header, reply_size).is_err() {
                        println!("Failed to send response to driver");
                        continue;
                    }
                }
            }
        });
        Ok(())
    }

    /// Close the communication with the driver
    pub fn close_driver_com(&self) {
        unsafe {
            CloseHandle::<HANDLE>(self.handle);
        }
    }
}

/// Check a USB device to allow it not
/// Return Ok(true) or Ok(false) according to the authorization
/// 
/// # Arguments
/// 
/// * 'content' - Content of the request from the driver
fn authorize_usb(content: &str) -> Result<bool, anyhow::Error> {
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
/// # Arguments
/// 
/// * 'usb_op' - Device wide filtering policy
/// * 'content' - Content of the driver request, it contains the path to the file
fn authorize_file(_usb_op: KeysasFilterOperation, content: &str) -> Result<bool, anyhow::Error> {
    let file_path = Path::new(content.trim_matches(char::from(0)));

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
        return Ok(true);
    }

    // Skip the directories
    if file_path.metadata()?.is_dir() {
        return Ok(true);
    }

    // Try to validate the file from the station report
    match validate_file(file_path) {
        Ok(true) => {
            return Ok(true);
        }
        _ => {
            println!("File not validated by station");
        }
    }

    // If the validation fails, ask the user authorization
    user_authorize_file(file_path)
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
fn validate_file(path: &Path) -> Result<bool, anyhow::Error> {
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
fn user_authorize_file(path: &Path) -> Result<bool, anyhow::Error> {
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
