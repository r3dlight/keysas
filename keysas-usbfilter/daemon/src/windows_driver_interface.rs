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
use std::mem::size_of;
use std::thread;
use widestring::U16CString;
use windows::core::{PCWSTR, PCSTR};
use windows::Win32::Foundation::{CloseHandle, BOOLEAN, HANDLE, STATUS_SUCCESS};
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterGetMessage, FilterReplyMessage, FILTER_MESSAGE_HEADER,
    FILTER_REPLY_HEADER,
};
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::s;

// Operation code for the request to userland
#[derive(Debug)]
enum KeysasFilterOperation {
	ScanFile = 0,				// Validate the signature of the file and the report
	UserAllowFile,			// Ask user to allow the file
	UserAllowAllUsb,			// Ask user to allow complete access the USB drive
	UserAllowUsbWithWarning // Ask user to allow access to USB drive with warning on file opening
}

#[derive(Debug)]
#[repr(C)]
struct DriverMessage {
    header: FILTER_MESSAGE_HEADER,
    operation: KeysasFilterOperation,
    path: [u16; 1024],
}

#[derive(Debug)]
#[repr(C)]
struct UserReply {
    header: FILTER_REPLY_HEADER,
    file_safe: BOOLEAN,
}

#[derive(Debug)]
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
            let request_size = u32::try_from(size_of::<DriverMessage>())?;
            let reply_size = u32::try_from(size_of::<FILTER_REPLY_HEADER>())?
                + u32::try_from(size_of::<BOOLEAN>())?;

            loop {
                let mut message = DriverMessage {
                    header: FILTER_MESSAGE_HEADER::default(),
                    operation: KeysasFilterOperation::ScanFile,
                    path: [0; 1024],
                };

                unsafe {
                    FilterGetMessage(handle, &mut message.header, request_size, None)?;
                }

                println!("{:?}", message);
                println!("Path: {:?}", String::from_utf16(&message.path)?);

                let file_path =  String::from_utf16(&message.path)?;
                let filename = format!("Allow file: {:?}", file_path.trim_matches(char::from(0)));
                let (name_ptr, _, _) = filename.into_raw_parts();
                let mut authorization_status = MESSAGEBOX_RESULT::default();
                unsafe {
                    authorization_status = MessageBoxA(
                        None,
                        PCSTR::from_raw(name_ptr),
                        s!("Keysas USB Filter"),
                        MB_YESNO | MB_ICONWARNING | MB_SYSTEMMODAL
                    );
                }

                let mut reply = match authorization_status {
                    IDYES => UserReply {
                                header: FILTER_REPLY_HEADER::default(),
                                file_safe: BOOLEAN::from(true),
                            },
                    IDNO => UserReply {
                                header: FILTER_REPLY_HEADER::default(),
                                file_safe: BOOLEAN::from(false),
                            },
                    _ => {
                        println!("Unknown Authorization: {:?}", authorization_status);
                        // By default block the access to the file
                        UserReply {
                            header: FILTER_REPLY_HEADER::default(),
                            file_safe: BOOLEAN::from(false),
                        }
                    }
                };

                reply.header.MessageId = message.header.MessageId;
                reply.header.Status = STATUS_SUCCESS;

                unsafe {
                    FilterReplyMessage(handle, &reply.header, reply_size)?;
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
