// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Connection to Keysas Windows service

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

use std::time::Duration;
use std::io;
use std::thread;
use tokio::net::windows::named_pipe::ClientOptions;
use tokio::time;
use windows_sys::Win32::Foundation::ERROR_PIPE_BUSY;
use anyhow::anyhow;

use crate::filter_store::FilterStore;

const SERVICE_PIPE: &str = r"\\.\pipe\keysas-service";

/// Initialize the pipe with Keysas Service and start a thread to monitor it
pub fn init_service_if(store: &FilterStore) -> Result<(), anyhow::Error> {
    // Initialize the client socket
    let client = loop {
        match ClientOptions::new().open(SERVICE_PIPE) {
            Ok(client) => break client,
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => (),
            Err(e) => return Err(anyhow!("Failed to open client socket")),
        }
        time::sleep(Duration::from_millis(50));
    };

    // Start the listening thread
    tokio::task::spawn(async {
        let mut msg = vec![0;1024];

        loop {
            client.readable().await;

            match client.try_read(&mut msg) {
                Ok(n) => {
                    msg.truncate(n);
                    println!("Message: {:?}", msg);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {continue;}
                Err(e) => {return;}
            }
        }
    });

    Ok(())
}