// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-in".
 *
 * (C) Copyright 2019-2023 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various funtions
 * for building the keysas-in binary.
 */

#![forbid(unsafe_code)]
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
#![feature(unix_socket_ancillary_data)]
use anyhow::{Context, Result};
use bincode::serialize;
use clap::{crate_version, Arg, ArgAction, Command};
use log::{debug, error, info};
use regex::Regex;
use std::ffi::OsStr;
use std::fs::File;
use std::os::unix::net::{SocketAncillary, UnixListener, UnixStream};
use std::path::PathBuf;
use std::process;
use std::thread as main_thread;
use std::time::Duration;

#[macro_use]
extern crate serde_derive;
use keysas_lib::{convert_ioslice, list_files, sha256_digest};

#[derive(Serialize, Debug, Clone)]
struct Message {
    filename: Box<OsStr>,
    digest: String,
}

struct Config {
    sas_in: String,
    socket: String,
    log_path: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sas_in: "/var/local/in/".to_string(),
            socket: "/run/keysas/sock_in".to_string(),
            log_path: "/var/log/keysas-in/".to_string(),
        }
    }
}

fn command_args(config: &mut Config) {
    let matches = Command::new("keysas-in")
        .version(crate_version!())
        .author("Stephane N.")
        .about("keysas-in, input SAS.")
        .arg(
            Arg::new("sas_in")
                .short('g')
                .long("sas_in")
                .value_name("Sets path for incoming directory")
                .default_value("/var/local/in/")
                .action(ArgAction::Set)
                .help("Path for incoming SAS"),
        )
        .arg(
            Arg::new("socket")
                .short('s')
                .long("socket")
                .value_name("Sets path for write-only socket")
                .default_value("/run/keysas/sock_in")
                .action(ArgAction::Set)
                .help("Path for write only abstract socket"),
        )
        .arg(
            Arg::new("log_path")
                .short('p')
                .long("log_path")
                .value_name("Sets path for the log file")
                .default_value("/var/log/keysas-in/")
                .action(ArgAction::Set)
                .help("Path to the log directory"),
        )
        .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .action(ArgAction::Version)
                .help("Print the version and exit"),
        )
        .get_matches();

    //Won't panic according to clap authors
    if let Some(p) = matches.get_one::<String>("sas_in") {
        config.sas_in = p.to_string();
    }
    if let Some(p) = matches.get_one::<String>("socket") {
        config.socket = p.to_string();
    }
    if let Some(p) = matches.get_one::<String>("log_path") {
        config.log_path = p.to_string();
    }
}

fn send_files(files: &Vec<String>, stream: &UnixStream, sas_in: &String) -> Result<()> {
    //Remove any file starting by .(dot)
    let re = Regex::new(r"^\.([a-z])*")?;
    let mut files = files.clone();
    files.retain(|x| !re.is_match(x));
    //Max X files per send in .chunks(X)
    for batch in files.chunks(2) {
        let (bufs, fhs): (Vec<Vec<u8>>, Vec<File>) = batch
            .iter()
            .map(|f| {
                let mut base_path = PathBuf::from(&sas_in);
                base_path.push(f);
                base_path
            })
            .filter_map(|f| {
                let digest = sha256_digest(&f.to_string_lossy()).unwrap();
                let m = Message {
                    filename: f.file_name()?.to_os_string().into(),
                    digest,
                };
                let data: Vec<u8> = match serialize(&m) {
                    Ok(d) => d,
                    Err(_e) => {
                        error!("Failed to serialize message");
                        return None;
                    }
                };

                let fh = match File::open(&f) {
                    Ok(f) => f,
                    Err(e) => {
                        error!("Failed to open file {}: {e}", f.display());
                        process::exit(1);
                    }
                };
                Some((data, fh))
            })
            .unzip();

        let (ios, fds) = convert_ioslice(fhs, &bufs);

        let mut ancillary_buffer = [0; 4096];
        let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);
        ancillary.add_fds(&fds[..]);
        match stream.send_vectored_with_ancillary(&ios[..], &mut ancillary) {
            Ok(_) => {
                debug!("Sent fds");
            }
            Err(e) => error!("Failed to send fds: {e}"),
        }
        //Not sure it is actually good
        for fd in fds {
            drop(fd);
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let mut config = Config::default();
    command_args(&mut config);
    info!("Keysas-in started :)");
    let sock = match UnixListener::bind(config.socket) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to open socket {e}");
            process::exit(1);
        }
    };

    loop {
        let (unix_stream, _sck_addr) = match sock.accept() {
            Ok(r) => r,
            Err(e) => {
                error!("Failed to accept connection: {e}");
                process::exit(1);
            }
        };

        let files = match list_files(&config.sas_in) {
            Ok(fs) => fs,
            Err(e) => {
                error!("Failed to list files in directory {}: {e}", &config.sas_in);
                process::exit(1);
            }
        };

        send_files(&files, &unix_stream, &config.sas_in)
            .context("Cannot send file descriptors :/")?;
        main_thread::sleep(Duration::from_millis(500));
    }
}
