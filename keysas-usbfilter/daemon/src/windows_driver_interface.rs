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
use wchar::wchar_t;
use widestring::U16CString;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{BOOLEAN, HANDLE, STATUS_SUCCESS, CloseHandle};
use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterGetMessage, FilterReplyMessage, FILTER_MESSAGE_HEADER,
    FILTER_REPLY_HEADER,
};

#[derive(Debug)]
#[repr(C)]
struct DriverMessage {
    header: FILTER_MESSAGE_HEADER,
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
        thread::spawn(move || {
            loop {
                let mut message = DriverMessage {
                    header: FILTER_MESSAGE_HEADER::default(),
                    path: [0; 1024],
                };
        
                unsafe {
                    FilterGetMessage(
                        handle,
                        &mut message.header,
                        u32::try_from(size_of::<DriverMessage>()).unwrap(),
                        None,
                    )
                    .unwrap();
                }
        
                println!("{:?}", message);
                println!("Path: {:?}", String::from_utf16(&message.path).unwrap());
        
                let mut reply = UserReply {
                    header: FILTER_REPLY_HEADER::default(),
                    file_safe: BOOLEAN::from(true),
                };
        
                reply.header.MessageId = message.header.MessageId;
                reply.header.Status = STATUS_SUCCESS;
        
                unsafe {
                    FilterReplyMessage(
                        handle,
                        &reply.header,
                        u32::try_from(size_of::<FILTER_REPLY_HEADER>()).unwrap()
                            + u32::try_from(size_of::<BOOLEAN>()).unwrap(),
                    )
                    .unwrap();
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