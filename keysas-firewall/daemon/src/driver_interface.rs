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
use std::mem::size_of;
use std::thread;
use libc::c_void;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use widestring::U16CString;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, HANDLE, STATUS_SUCCESS, GetLastError
};
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterGetMessage, FilterReplyMessage, FilterSendMessage,
    FILTER_MESSAGE_HEADER, FILTER_REPLY_HEADER
};

use crate::controller::ServiceController;

/// Operation code for the request from a driver to userland
#[derive(Debug, Clone, Copy)]
pub enum KeysasFilterOperation {
    /// Validate the signature of the file and the report
    ScanFile = 0,
    /// Ask to validate the USB drive signature
    ScanUsb
}

/// Authorization states for files and USB devices
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum KeysasAuthorization {
    /// Default value
    AuthUnknown,
    /// Authorization request pending
    AuthPending,
    /// Access is blocked
    AuthBlock,
    /// Access is allowed in read mode only
    AuthAllowRead,
    /// Access is allowed with a warning to the user
    AuthAllowWarning,
    /// Access is allowed for all operations
    AuthAllowAll
}

impl KeysasAuthorization {
    pub fn as_u8(&self) -> u8 {
        match self {
            Self::AuthUnknown => 0,
            Self::AuthPending => 1,
            Self::AuthBlock => 2,
            Self::AuthAllowRead => 3,
            Self::AuthAllowWarning => 4,
            Self::AuthAllowAll => 5
        }
    }
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
    /// Result of the request => the authorization state to apply to the file or USB device
    result: KeysasAuthorization,
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

    /// Start listening to the drivers' requests
    ///
    /// # Arguments
    ///
    /// * `cb` - Callback to handle the driver requests
    pub fn start_driver_com(&self, ctrl: &Arc<ServiceController>) -> Result<(), anyhow::Error> {
        let handle = self.handle;
        let ctrl_hdl = ctrl.clone();
        thread::spawn(move || -> Result<(), anyhow::Error> {
            // Pre compute the request and response size
            let request_size = u32::try_from(size_of::<DriverRequest>())?;
            let reply_size = u32::try_from(size_of::<FILTER_REPLY_HEADER>())?
                + u32::try_from(size_of::<KeysasAuthorization>())?;

            loop {
                // Wait for a request from the driver
                let mut request = DriverRequest {
                    header: FILTER_MESSAGE_HEADER::default(),
                    operation: KeysasFilterOperation::ScanUsb,
                    content: [0; 1024],
                };

                unsafe {
                    if FilterGetMessage(handle, &mut request.header, request_size, None).is_err()
                    {
                        println!("Failed to get message from driver");
                        continue;
                    }
                }

                // Dispatch the request
                let result = match ctrl_hdl.handle_driver_request(request.operation, &request.content) {
                    Ok(r) => r,
                    Err(e) => {
                        println!("Failed to handle driver request: {e}");
                        KeysasAuthorization::AuthBlock
                    }
                };

                println!("Sending authorization: {:?}", result);

                // Prepare the response and send it
                let reply = UserReply {
                    header: FILTER_REPLY_HEADER {
                        MessageId: request.header.MessageId,
                        Status: STATUS_SUCCESS,
                    },
                    result,
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

    pub fn send_msg(&self, msg: &[u8]) -> Result<(), anyhow::Error> {
        let mut nb_bytes_ret: u32 = 0;
        unsafe {
            if let Err(_) = FilterSendMessage(
                self.handle,
                msg as *const _ as *const c_void,
                msg.len().try_into()?,
                None,
                0,
                &mut nb_bytes_ret as *mut u32
            ) {
                if let Err(e) = GetLastError() {
                    println!("Error: {:?}", e.message().to_string_lossy());
                }
                return Err(anyhow!("Failed to send message to driver"));
            }
        }

        // TODO - Handle response from driver

        Ok(())
    }

    /// Close the communication with the driver
    pub fn close_driver_com(&self) {
        unsafe {
            let _ = CloseHandle::<HANDLE>(self.handle);
        }
    }
}