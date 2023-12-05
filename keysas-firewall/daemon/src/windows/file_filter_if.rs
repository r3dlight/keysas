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
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]

use anyhow::anyhow;
use std::mem::size_of;
use std::thread;
use std::ffi::OsString;
use std::sync::{Arc, Mutex};
use widestring::U16CString;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterGetMessage, FILTER_MESSAGE_HEADER, FILTER_REPLY_HEADER, FilterReplyMessage
};
use windows::Win32::Foundation::STATUS_SUCCESS;

use crate::controller::{FileAuthorization, FilteredFile, ServiceController};
use crate::file_filter_if::FileFilterInterface;

/// Operation code for the request from a driver to userland
#[derive(Debug, Clone, Copy)]
pub enum KeysasFilterOperation {
    /// Validate the signature of the file and the report
    ScanFile = 0,
    /// Ask to validate the USB drive signature
    ScanUsb,
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
    result: FileAuthorization,
}

/// Handle to the driver interface
#[derive(Debug, Copy, Clone)]
pub struct WindowsFileFilterInterface {
    /// Handle to the communication port
    handle: HANDLE,
}

impl WindowsFileFilterInterface {
    /// Initialize the interface to the Windows driver
    /// The connection is made with the name in DRIVER_COM_PORT
    pub fn init() -> Result<WindowsFileFilterInterface, anyhow::Error> {
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
}

/// Name of the communication port with the driver
const DRIVER_COM_PORT: &str = "\\KeysasPort";

impl FileFilterInterface for WindowsFileFilterInterface {
    /// Start listening to the drivers' requests
    ///
    /// # Arguments
    ///
    /// * `cb` - Callback to handle the driver requests
    fn start(&self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error> {
        let handle = self.handle;
        let ctrl_hdl = ctrl.clone();
        thread::spawn(move || -> Result<(), anyhow::Error> {
            // Pre compute the request and response size
            let request_size = u32::try_from(size_of::<DriverRequest>())?;
            let reply_size = u32::try_from(size_of::<FILTER_REPLY_HEADER>())?
                + u32::try_from(size_of::<FileAuthorization>())?;

            loop {
                // Wait for a request from the driver
                let mut request = DriverRequest {
                    header: FILTER_MESSAGE_HEADER::default(),
                    operation: KeysasFilterOperation::ScanUsb,
                    content: [0; 1024],
                };

                unsafe {
                    if FilterGetMessage(handle, &mut request.header, request_size, None).is_err() {
                        println!("Failed to get message from driver");
                        continue;
                    }
                }

                println!("Minifilter request: {:?}", request);

                // Extract information about the file
                let mut file = FilteredFile {
                    path: Some(OsString::from(String::from_utf16(&request.content[32..])?)),
                    id: [0; 32]
                };

                for i in 0..16 {
                    let bytes = request.content[i].to_le_bytes();
                    file.id[i*2] = bytes[0];
                    file.id[i*2+1] = bytes[1]; 
                }

                // Ask controler for authorization
                let result = {
                    let controler = ctrl_hdl.lock().unwrap();
                
                    match controler.authorize_file(&file, true) {
                        Ok(r) => FileAuthorization::AllowRead,
                        Err(e) => {
                            println!("Failed to handle driver request: {e}");
                            FileAuthorization::Block
                        }
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

    /// Update the control policy on a file
    ///
    /// # Arguments
    ///
    /// `update` - Information on the file and the new authorization status
    fn update_file_auth(&self, _update: &FilteredFile) -> Result<(), anyhow::Error> {
        todo!()
        // let mut nb_bytes_ret: u32 = 0;
        // unsafe {
        //     if let Err(_) = FilterSendMessage(
        //         self.handle,
        //         msg as *const _ as *const c_void,
        //         msg.len().try_into()?,
        //         None,
        //         0,
        //         &mut nb_bytes_ret as *mut u32
        //     ) {
        //         let err = GetLastError();
        //         println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
        //         return Err(anyhow!("Failed to send message to driver"));
        //     }
        // }

        // // TODO - Handle response from driver

        // Ok(())
    }

    /// Close the communication with the driver
    fn stop(self: Box<Self>) {
        unsafe {
            CloseHandle::<HANDLE>(self.handle);
        }
    }
}
