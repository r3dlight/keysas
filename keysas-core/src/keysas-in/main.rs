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
//#![warn(unstable_features)]
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
use std::fs;
use std::fs::File;
use std::io::IoSlice;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{SocketAncillary, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread as main_thread;
use std::time::Duration;

#[macro_use]
extern crate serde_derive;
use keysas_lib::{list_files, sha256_digest};

#[derive(Serialize, Debug)]
struct Message {
    filename: String,
    digest: String,
}

struct Config {
    sas_in: String,
    socket: String,
    log_path: String,
    file_max_size: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sas_in: "/var/local/in/".to_string(),
            socket: "/run/keysas/sock_in".to_string(),
            log_path: "/var/log/keysas-in/".to_string(),
            file_max_size: 500000,
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
                .default_value("/run/keysas/sock")
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

fn main() -> Result<()> {
    let mut config = Config::default();
    command_args(&mut config);
    keysas_lib::init_logger();

    if Path::new(&config.socket).exists() {
        fs::remove_file(&config.socket).expect("Cannot remove socket");
        debug!("Cleaning previous socket_in");
    }

    let sock = UnixListener::bind(config.socket).context("Could not create the unix socket")?;
    //let sock = UnixStream::connect(socket_path)?;
    // put the server logic in a loop to accept several connections
    loop {
        let (unix_stream, _socket_address) = sock
            .accept()
            .context("Failed at accepting a connection on the unix listener")?;
        let files = list_files(&config.sas_in)?;
        for filename in files {
            //spawn a thread here to handle streams

            info!("Passing file descriptor of file: {}", filename);
            handle_stream(unix_stream.try_clone()?, &config.sas_in, filename)?;
        }
        main_thread::sleep(Duration::from_millis(500));
    }
}

fn handle_stream(stream: UnixStream, sas_in: &String, filename: String) -> Result<()> {
    // to be filled
    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);
    let mut path_file = PathBuf::new();
    path_file.push(sas_in);
    path_file.push(&filename);
    let digest = sha256_digest(path_file.to_str().unwrap())?;
    let fd = File::open(&path_file)?;
    ancillary.add_fds(&[fd.as_raw_fd()][..]);

    let data = serialize(&Message {
        filename: filename.clone(),
        digest: digest,
    })?;
    let bufs = &mut [IoSlice::new(&data[..])][..];
    //let mut bufs = &mut [IoSlice::new(&buf[..])][..];
    stream.send_vectored_with_ancillary(bufs, &mut ancillary)?;
    info!(
        "File descriptor now closed, removing: {}",
        path_file.display()
    );
    fs::remove_file(path_file)?;
    Ok(())
}
