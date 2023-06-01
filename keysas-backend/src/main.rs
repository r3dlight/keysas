// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-sign".
 *
 * (C) Copyright 2019-2023 Stephane Neveu
 *
 * The code for keysas-sign binary.
 */

use std::{net::TcpListener, path::Path, thread::spawn};

use anyhow::Result;
use http::header::HeaderValue;
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus, ABI,
};
use nom::bytes::complete::take_until;
use nom::IResult;
use regex::Regex;
use std::fs;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::Duration;
use tungstenite::{
    accept_hdr,
    handshake::server::{Request, Response},
    Message,
};

extern crate serde;
extern crate serde_json;
#[macro_use]
extern crate serde_derive;

extern crate libc;
extern crate regex;
mod errors;

#[derive(Serialize, Deserialize, Debug)]
pub struct GlobalStatus {
    health: Daemons,
    guichetin: GuichetState,
    guichettransit: bool,
    guichetout: GuichetState,
    has_signed_once: bool,
    keypair_generated: bool,
    ip: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Daemons {
    pub status_in: bool,
    pub status_transit: bool,
    pub status_out: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct GuichetState {
    pub name: String,
    //pub detected: bool,
    //pub waiting: bool,
    //pub writing: bool,
    pub analysing: bool,
    //pub reading: bool,
    //pub done: bool,
    pub files: Vec<String>,
}

fn landlock_sandbox() -> Result<(), RulesetError> {
    let abi = ABI::V1;
    let status = Ruleset::new()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        // Read-only access to /usr, /etc and /dev.
        .add_rules(path_beneath_rules(
            &[
                "/usr", "/etc", "/dev", "/home", "/tmp", "/var", "/run", "/proc",
            ],
            AccessFs::from_read(abi),
        ))?
        // Read-write access to /home and /tmp.
        //.add_rules(path_beneath_rules(&["/home", "/tmp"], AccessFs::from_all(abi)))?
        .restrict_self()?;
    match status.ruleset {
        // The FullyEnforced case must be tested by the developer.
        RulesetStatus::FullyEnforced => println!("Landlock: Fully sandboxed."),
        RulesetStatus::PartiallyEnforced => println!("Landlock: Partially sandboxed."),
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => {
            println!("Landlock: Not sandboxed! Please update your kernel.")
        }
    }
    Ok(())
}

/// List files in a directory except hidden ones
pub fn list_files(directory: &str) -> Result<Vec<String>> {
    let paths: std::fs::ReadDir = fs::read_dir(directory)?;
    let mut names = paths
        .filter_map(|entry| {
            entry.ok().and_then(|e| {
                e.path()
                    .file_name()
                    .and_then(|n| n.to_str().map(String::from))
            })
        })
        .collect::<Vec<String>>();
    // Not sending any files starting with dot like .bashrc
    let re = Regex::new(r"^\.([a-z])*")?;
    names.retain(|x| !re.is_match(x));
    Ok(names)
}

pub fn daemon_status() -> Result<[bool; 3]> {
    let mut state: [bool; 3] = [true, true, true];

    let output = Command::new("systemctl")
        .arg("status")
        .arg("keysas-in.service")
        .output()
        .expect("failed to get status for keysas-in");
    let status_in = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"Active: active")?;
    if re.is_match(&status_in) {
        state[0] = true;
    } else {
        state[0] = false;
    }
    let output = Command::new("systemctl")
        .arg("status")
        .arg("keysas-transit.service")
        .output()
        .expect("failed to get status for keysas-transit");
    let status_in = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"Active: active")?;
    if re.is_match(&status_in) {
        state[1] = true;
    } else {
        state[1] = false;
    }
    let output = Command::new("systemctl")
        .arg("status")
        .arg("keysas-out.service")
        .output()
        .expect("failed to get status for keysas-out");
    let status_in = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(r"Active: active")?;
    if re.is_match(&status_in) {
        state[2] = true;
    } else {
        state[2] = false;
    }
    Ok(state)
}

fn parse_ip(s: &str) -> IResult<&str, &str> {
    take_until(":")(s)
}

fn get_ip() -> Result<Vec<String>> {
    let mut ips = Vec::new();
    let addrs = nix::ifaddrs::getifaddrs().unwrap();
    for ifaddr in addrs {
        if let Some(address) = ifaddr.address {
            let addr = address.to_string();
            let (_, ip) = parse_ip(&addr).unwrap();
            //TODO: should be fixed to match other eth names
            if ifaddr.interface_name == "eth0" && ip.parse::<Ipv4Addr>().is_ok() {
                ips.push(ip.to_string());
            }
        }
    }
    Ok(ips)
}

fn main() -> Result<()> {
    landlock_sandbox()?;
    let server = TcpListener::bind("127.0.0.1:3012")?;
    for stream in server.incoming() {
        println!("keysas-backend: Received a new websocket handshake.");
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to accept client connection: {}", e);
                continue;
            }
        };
        spawn(move || -> Result<()> {
            let callback = |_req: &Request, mut response: Response| {
                log::info!("keysas-backend: Received a new websocket handshake.");
                //let headers = response.headers_mut();
                //headers.append("KeysasBackend", "true".parse().unwrap());
                response.headers_mut().append(
                    "Sec-WebSocket-Protocol",
                    HeaderValue::from_static("websocket"),
                );
                //println!("Response: {response:?}");
                Ok(response)
            };
            let mut websocket = accept_hdr(stream, callback)?;

            loop {
                let files_in = list_files("/var/local/in");
                let files_out = list_files("/var/local/out");

                let mut fs_in = PathBuf::new();
                fs_in.push("/var/local/in");
                let is_empty_fs_in = fs_in.read_dir()?.next().is_none();

                let mut fs_transit = PathBuf::new();
                fs_transit.push("/var/local/transit");
                let is_empty_fs_transit = fs_transit.read_dir()?.next().is_none();

                let working_in =
                    Path::new("/var/lock/keysas/keysas-in").exists() || !is_empty_fs_in;

                let working_out =
                    Path::new("/var/lock/keysas/keysas-out").exists() || !is_empty_fs_transit;

                let working_transit = Path::new("/var/lock/keysas/keysas-transit").exists();

                let health: Daemons = Daemons {
                    status_in: daemon_status()?[0],
                    status_transit: daemon_status()?[1],
                    status_out: daemon_status()?[2],
                };
                let guichet_state_in: GuichetState = GuichetState {
                    name: String::from("GUICHET-IN"),
                    analysing: working_in,
                    files: files_in?,
                };
                let guichet_state_out: GuichetState = GuichetState {
                    name: String::from("GUICHET-OUT"),
                    analysing: working_out,
                    files: files_out?,
                };
                let mut has_signed = false;

                if !Path::new("/usr/share/keysas/neversigned").exists() {
                    has_signed = true;
                }
                let mut keypair_ok = false;

                if Path::new("/etc/keysas/keysas.priv").exists()
                    && Path::new("/etc/keysas/keysas.pub").exists()
                {
                    keypair_ok = true;
                }

                let orders = GlobalStatus {
                    health,
                    guichetin: guichet_state_in,
                    guichettransit: working_transit,
                    guichetout: guichet_state_out,
                    has_signed_once: has_signed,
                    keypair_generated: keypair_ok,
                    ip: get_ip()?,
                };

                let serialized = serde_json::to_string(&orders)?;
                websocket.write_message(Message::Text(serialized))?;
                thread::sleep(Duration::from_millis(100));
            }
        });
    }
    Ok(())
}
