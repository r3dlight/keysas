// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Interface to the user tray application

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
use serde::{Deserialize, Serialize};
use libmailslot;

/// Message for a file status notification
#[derive(Debug, Deserialize, Serialize, Clone)]
struct FileUpdateMessage {
    device: String,
    path: String,
    authorization: bool
}

/// Name of the communication pipe
const SERVICE_PIPE: &str = r"\\.\mailslot\keysas\service-to-app";
const TRAY_PIPE: &str = r"\\.\mailslot\keysas\app-to-service";

/// Initialize the server behind the interface
pub fn init() -> Result<(), anyhow::Error> {
    // Initialize the server in a separate thread
    std::thread::spawn(|| {
        let server = match libmailslot::create_mailslot(TRAY_PIPE) {
            Ok(s) => s,
            Err(_) => return (),
        };

        loop {
            while let Ok(Some(msg)) = libmailslot::read_mailslot(&server) {
                if let Ok(update) = serde_json::from_slice::<FileUpdateMessage>(msg.as_bytes()) {
                    println!("message from tray {:?}", update);
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }

    });
    Ok(())
}

/// Try to send a message to the connected socket
pub fn send(msg: &impl Serialize) -> Result<(), anyhow::Error> {
    let msg_vec = match serde_json::to_string(msg) {
        Ok(m) => m,
        Err(e) => return Err(anyhow!("Failed to serialize message: {e}"))
    };

    if let Err(e) = libmailslot::write_mailslot(SERVICE_PIPE, &msg_vec) {
        return Err(anyhow!("Failed to post message to the mailslot: {e}"));
    }

    Ok(())
}

pub fn send_file_auth_status(path: &str, authorized: bool) -> Result<(), anyhow::Error> {
    let msg = FileUpdateMessage {
        device: String::from("D:"),
        path: String::from(path),
        authorization: authorized
    };

    send(&msg)
}