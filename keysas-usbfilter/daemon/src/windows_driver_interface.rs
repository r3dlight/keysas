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
use std::ffi::OsStr;
use std::fs::File;
use std::io::BufReader;
use std::io::Read;
use std::mem::size_of;
use std::path::PathBuf;
use std::path::{Component, Path};
use std::thread;
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
use base64::{engine::general_purpose, Engine as _};
use x509_cert::Certificate;
use ed25519_dalek::{self, Digest, Sha512};
use pkcs8::der::{DecodePem, EncodePem};
use oqs::sig::{Algorithm, Sig};

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

/// Metadata object in the report.
/// The structure can be serialized to JSON.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct MetaData {
    /// Name of the file
    name: String,
    /// Date of the report creation
    date: String,
    /// Type of the file
    file_type: String,
    /// True if the file is correct
    is_valid: bool,
    /// Object containing the detailled [FileReport]
    report: FileReport,
}

/// Signature binding the file and the report.
/// the structure can be serialized to JSON.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Bd {
    /// SHA256 digest of the file encoded in base64
    file_digest: String,
    /// SHA256 digest of the [MetaData] associated to the file
    metadata_digest: String,
    /// Station certificates: concatenation of its ED25519 and Dilithium5 signing certificates with a '|' delimiter
    station_certificate: String,
    /// Report signature: concatenation of the ED25519 and Dilithium5 signatures in base64
    report_signature: String,
}

/// Report that will be created for each file.
/// The structure can be serialized to JSON.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct Report {
    /// [MetaData] of the file analysis
    metadata: MetaData,
    /// [Bd] binding of the file and the report with the station signature
    binding: Bd,
}

/// Detailed report of the file checks.
#[derive(Debug, Serialize, Deserialize, Clone)]
struct FileReport {
    /// Detailed report of the yara checks
    yara: String,
    /// Detailed report of the clamav checks
    av: Vec<String>,
    /// True if the file type is allowed
    type_allowed: bool,
    /// Size of the file
    size: u64,
    /// True if a file corruption occured during the file processing
    corrupted: bool,
    /// True if the file size is too big
    toobig: bool,
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

                println!("Sent response");
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
    let file_path = Path::new(content.trim_matches(char::from(0)));

    // Try to get the parent directory
    let mut components = file_path.components();
    println!("Path components: {:?}", components);

    // First component is the Root Directory
    // If the second directory is "System Volume Information" then it is internal to windows, skip it
    loop {
        let c = components.next();
        if c == Some(Component::RootDir) {
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
    if path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("krp"))
    {
        // If yes validate it alone
        return validate_report_alone(path);
    }

    // If not try to find the corresponding report
    // It should be in the same directory with the same name + '.krp'
    let report_path = path.to_path_buf().join(".krp");
    match File::open(report_path.as_path()) {
        Ok(report) => {
            // If a corresponding report is found then validate both the file and the report
            return validate_file_and_report(path, report_path.as_path());
        }
        Err(_) => {
            // There is no corresponding report for validating the file
            return Ok(false);
        }
    }
}

fn parse_report(report_path: &Path) -> Result<Report, anyhow::Error> {
    let report_content = match std::fs::read_to_string(report_path) {
        Ok(ct) => ct,
        Err(_) => {
            println!("Failed to read report content");
            return Err(anyhow!("Failed to read report content"));
        }
    };
    let report: Report = serde_json::from_str(report_content.as_str())?;

    println!("Report: {:?}", report);

    let mut certs = report.binding.station_certificate.split('|');
    // TODO: remove unwraps
    let cert_cl = Certificate::from_pem(certs.next().unwrap())?;
    let cert_pq = Certificate::from_pem(certs.remainder().unwrap())?;

    let pub_cl = ed25519_dalek::PublicKey::from_bytes(
        cert_cl
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .raw_bytes(),
    )?;

    oqs::init();
    let pq_scheme = Sig::new(Algorithm::Dilithium5).unwrap();
    let pub_pq = pq_scheme
        .public_key_from_bytes(
            cert_pq
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
        )
        .unwrap();

    // Verify the signature of the report
    let signature = general_purpose::STANDARD
        .decode(&report.binding.report_signature)?;
    let concat = format!(
        "{}-{}",
        String::from_utf8(
            general_purpose::STANDARD
                .decode(&report.binding.file_digest)?
        )?,
        String::from_utf8(
            general_purpose::STANDARD
                .decode(&report.binding.metadata_digest)?
        )?
    );

    let mut prehashed = Sha512::new();
    prehashed.update(&concat);
    /*
    assert_eq!(
        true,
        pub_cl
            .verify_prehashed(
                prehashed,
                None,
                &ed25519_dalek::Signature::from_bytes(
                    &signature[0..ed25519_dalek::SIGNATURE_LENGTH]
                )
                .unwrap()
            )
            .is_ok()
    );

    assert_eq!(
        true,
        pq_scheme
            .verify(
                concat.as_bytes(),
                pq_scheme
                    .signature_from_bytes(&signature[ed25519_dalek::SIGNATURE_LENGTH..])
                    .unwrap(),
                pub_pq
            )
            .is_ok()
    );
    */
    Ok(report)
}

fn validate_report_alone(report_path: &Path) -> Result<bool, anyhow::Error> {
    let report = match parse_report(report_path) {
        Ok(rp) => rp,
        Err(e) => {
            println!("Failed to parse report");
            return Ok(false);
        }
    };
    Ok(true)
}

fn validate_file_and_report(file: &Path, report_path: &Path) -> Result<bool, anyhow::Error> {
    let report = match parse_report(report_path) {
        Ok(rp) => rp,
        Err(e) => {
            println!("Failed to parse report");
            return Ok(false);
        }
    };

    // Compute hash of the file
    Ok(true)
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
