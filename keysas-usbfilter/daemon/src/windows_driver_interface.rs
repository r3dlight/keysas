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
use libc::c_void;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::mem::size_of;
use std::path::PathBuf;
use std::path::{Component, Path};
use std::thread;
use std::os::windows::ffi::OsStrExt;
use std::ffi::{OsStr, OsString};
use widestring::U16CString;
use windows::core::{PCSTR, PCWSTR};
use windows::s;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, BOOL, BOOLEAN, HANDLE, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, ReadFile, SetFilePointer, FILE_ATTRIBUTE_NORMAL, FILE_BEGIN,
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE,
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

// Operation code for the request to userland
#[derive(Debug)]
enum KeysasFilterOperation {
    ScanFile = 0,            // Validate the signature of the file and the report
    UserAllowFile,           // Ask user to allow the file
    ScanUsb,                 // Ask to validate the USB drive signature
    UserAllowAllUsb,         // Ask user to allow complete access the USB drive
    UserAllowUsbWithWarning, // Ask user to allow access to USB drive with warning on file opening
}

#[derive(Debug)]
#[repr(C)]
struct DriverRequest {
    header: FILTER_MESSAGE_HEADER,
    operation: KeysasFilterOperation,
    content: [u16; 1024],
}

#[derive(Debug)]
#[repr(C)]
struct UserReply {
    header: FILTER_REPLY_HEADER,
    result: BOOLEAN,
}

#[derive(Debug, Copy, Clone)]
pub struct WindowsDriverInterface {
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

        let handle;

        unsafe {
            handle = match FilterConnectCommunicationPort(PCWSTR(com_port_name), 0, None, 0, None) {
                Ok(h) => h,
                Err(e) => {
                    log::error!("Connection to minifilter failed: {e}");
                    return Err(anyhow!("Connection to minifilter failed: {e}"));
                }
            };
        }

        Ok(Self { handle })
    }

    /// Start listening to the drivers' requests and register a callback to handle them
    ///
    /// # Arguments
    ///
    /// * `cb` - Callback to handle the driver requests
    pub fn start_driver_com(&self, _cb: fn() -> ()) -> Result<(), anyhow::Error> {
        let handle = self.handle.clone();
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
                    if let Err(_) =
                        FilterGetMessage(handle, &mut request.header, request_size, None)
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
                            if let Err(_) = FilterReplyMessage(handle, &reply.header, reply_size) {
                                println!("Failed to send response to driver");
                            }
                        }
                        continue;
                    }
                };

                // Dispatch the request
                let result = match request.operation {
                    KeysasFilterOperation::ScanFile | KeysasFilterOperation::UserAllowFile => {
                        match authorize_file(request.operation, &content) {
                            Ok(true) => true,
                            _ => false,
                        }
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
                    if let Err(_) = FilterReplyMessage(handle, &reply.header, reply_size) {
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

fn authorize_usb(content: &str) -> Result<bool, anyhow::Error> {
    println!("Received USB scan request: {:?}", content);
    let mut device = HANDLE::default();
    let mut buffer: [u8; 4096] = [0; 4096];
    let mut byte_read: u32 = 0;

    // Open the device on the first sector
    unsafe {
        device = match CreateFileA(
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
    }

    if device.is_invalid() {
        println!("Invalid device handle");
        return Err(anyhow!("Invalid device handle"));
    }

    let mut vde = VOLUME_DISK_EXTENTS::default();
    let mut dw: u32 = 0;
    let mut res = BOOL::from(false);

    unsafe {
        res = DeviceIoControl(
            device,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            None,
            0,
            Some(&mut vde as *mut _ as *mut c_void),
            u32::try_from(size_of::<VOLUME_DISK_EXTENTS>())?,
            Some(&mut dw),
            None,
        );
    }

    let mut drive_path = String::from("\\\\.\\PhysicalDrive");
    drive_path.push_str(&vde.Extents[0].DiskNumber.to_string());

    println!("Physical Drive path: {:?}", drive_path);

    let drive_str = PCSTR::from_raw(drive_path.as_ptr() as *const u8);
    unsafe {
        println!("Physical Drive path windows: {:?}", drive_str.to_string()?);
    }

    let mut handle_usb = HANDLE::default();
    unsafe {
        handle_usb = match CreateFileA(
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
    }

    if handle_usb.is_invalid() {
        println!("Invalid device usb handle");
        return Err(anyhow!("Invalid device usb handle"));
    }

    // Move the file pointer after the MBR table (512B)
    // and read the signature content
    let mut read = BOOL::from(false);
    unsafe {
        //SetFilePointer(device, 512, None, FILE_BEGIN);
        read = ReadFile(
            handle_usb,
            Some(buffer.as_mut_ptr() as *mut c_void),
            4096,
            Some(&mut byte_read),
            None,
        );
    }

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

fn authorize_file(op: KeysasFilterOperation, content: &str) -> Result<bool, anyhow::Error> {
    let mut file_path = Path::new(content.trim_matches(char::from(0)));

    // Try to get the parent directory
    let mut components = file_path.components();

    // First component is the Root Directory
    // If the second directory is "System Volume Information" then it is internal to windows, skip it
    loop {
        let c = components.next();
        if None == c || c == Some(Component::RootDir) {
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
    return user_authorize_file(file_path);
}

fn validate_file(path: &Path) -> Result<bool, anyhow::Error> {
    // Test if the file is a station report
    if Path::new(path)
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("krp"))
    {
        // If yes validate it alone
        if let Err(e) = parse_report(Path::new(path), None, None, None) {
            println!("Failed to parse report: {e}");
            return Ok(false);
        }
        return Ok(true);
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
            return Ok(true);
        }
        false => {
            // There is no corresponding report for validating the file
            println!("No report found at {:?}", path_report);
            return Ok(false);
        }
    }
}

fn user_authorize_file(path: &Path) -> Result<bool, anyhow::Error> {
    // Find authorization status for the file
    let mut authorization_status = MESSAGEBOX_RESULT::default();
    let auth_request = format!("Allow file: {:?}", path.as_os_str());
    let (auth_request_ptr, _, _) = auth_request.into_raw_parts();

    unsafe {
        authorization_status = MessageBoxA(
            None,
            PCSTR::from_raw(auth_request_ptr),
            s!("Keysas USB Filter"),
            MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL,
        );
    }

    match authorization_status {
        IDYES => {
            return Ok(true);
        }
        IDNO => {
            return Ok(false);
        }
        _ => {
            return Err(anyhow!(format!(
                "Unknown Authorization: {:?}",
                authorization_status
            )));
        }
    };
}
