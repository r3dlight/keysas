// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Simple wrapper around the Windows mailslot API

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
use windows::Win32::Foundation::{HANDLE, GetLastError};
use windows::Win32::System::Mailslots::{GetMailslotInfo, CreateMailslotA};
use windows::Win32::System::SystemServices::MAILSLOT_WAIT_FOREVER;
use windows::Win32::Storage::FileSystem::{CreateFileA, WriteFile, ReadFile, FILE_SHARE_READ,
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL};
use windows::core::PCSTR;
use libc::c_void;
use std::str;

const MAX_MSG_SIZE: u32 = 1024;

/// Handle to the mailslot
#[derive(Debug, Copy, Clone)]
pub struct MailSlot {
    pub handle: HANDLE
}

/// Create a new mailslot
/// 
/// # Arguments
/// 
/// * `name` - Name of the mailslot
pub fn create_mailslot(name: &str) -> Result<MailSlot, anyhow::Error> {
    let slot_name = PCSTR::from_raw(name.as_ptr() as *const u8);
    let handle = unsafe {
        match CreateMailslotA(
            slot_name,
            MAX_MSG_SIZE,
            MAILSLOT_WAIT_FOREVER,
            None
        ) {
            Ok(h) => h,
            Err(_) => {
                println!("create_mailslot: Failed to create mailslot: {:?}", name);
                let err = GetLastError();
                println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
                return Err(anyhow!("create_mailslot: Failed to create mailslot"));
            }
        }
    };

    if handle.is_invalid() {
        println!("create_mailslot: Invalid mailslot handle");
        unsafe {
            let err = GetLastError();
            println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
        }
        return Err(anyhow!("create_mailslot: Invalid mailslot handle"));

    }

    Ok(MailSlot{handle})
}

/// Read one message from the mailslot
/// 
/// # Arguments
/// 
/// * `mailslot` - Handle to the mailslot
/// * `handle_msg` - Callback to handle messages received
pub fn read_mailslot(mailslot: &MailSlot) -> Result<Option<String>, anyhow::Error> {
    // Retrieve state of the mailslot
    let mut next_msg_size: u32 = 0;
    let mut nb_msg: u32 = 0;
    unsafe {
        if !GetMailslotInfo(
            mailslot.handle,
            None,
            Some(&mut next_msg_size),
            Some(&mut nb_msg),
            None
        ).as_bool() {
            println!("read_mailslot: Failed to read mailslot info");
            let err = GetLastError();
            println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
            return Err(anyhow!("read_mailslot: Failed to read mailslot info"));
        }
    }

    // If there is no message to read exit
    if nb_msg == 0 {
        return Ok(None);
    }

    // Read the message from the mailslot
    let mut buffer: [u8; MAX_MSG_SIZE as usize] = [0; MAX_MSG_SIZE as usize];
    unsafe {
        if !ReadFile(
            mailslot.handle,
            Some(buffer.as_mut_ptr() as *mut c_void),
            next_msg_size,
            None,
            None
        ).as_bool() {
            println!("read_mailslot: Failed to read message");
            let err = GetLastError();
            println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
            return Err(anyhow!("read_mailslot: Failed to read message"));
        }
    }

    match str::from_utf8(&buffer) {
        Ok(msg) => {return Ok(Some(String::from(msg)));}
        Err(e) => {return Err(anyhow!("read_mailslot: Failed to read message {e}"));}
    }
}

/// Write a message to a mailbox
/// 
/// # Arguments
/// 
/// * `name` - Name of the mailslot
/// * `message` - Message to write
pub fn write_mailslot(name: &str, message: &str) -> Result<(), anyhow::Error> {
    // Check that message is no longer than the maximum message size
    // Conversion from u32 to usize should not panic as usize should be at least 32 bit wide on targets
    if message.len() > usize::try_from(MAX_MSG_SIZE).unwrap() {
        println!("write_mailslot: message too long");
        return Err(anyhow!("write_mailslot: message too long"));
    }

    // The mailslot is accessed like a file
    // Create a handle to the file
    let slot_name = PCSTR::from_raw(name.as_ptr() as *const u8);
    let tmp_handle = HANDLE::default();
    // GENERIC_WRITE corresponds to the 30th bit of the mask
    //  according to https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask-format
    let generic_write_val: u32 = 0x40000000;
    let handle = unsafe {
        match CreateFileA(
            slot_name,
            generic_write_val,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            tmp_handle
        ) {
            Ok(h) => h,
            Err(_) => {
                println!("write_mailslot: Failed to create file");
                let err = GetLastError();
                println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
                return Err(anyhow!("write_mailslot: Failed to create file"));
            }
        }
    };

    if handle.is_invalid() {
        println!("write_mailslot: Invalid mailslot handle");
        unsafe {
            let err = GetLastError();
            println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
        }
        return Err(anyhow!("write_mailslot: Invalid mailslot handle"));

    }

    // Write to the file
    unsafe {
        if !WriteFile(
            handle,
            Some(message.as_bytes()),
            None,
            None
        ).as_bool() {
            println!("write_mailslot: Failed to write to file");
            let err = GetLastError();
            println!("Error: {:?}", err.to_hresult().message().to_string_lossy());
            return Err(anyhow!("write_mailslot: Failed to write to file"));
        }
    }

    Ok(())
}