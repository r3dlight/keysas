// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-out".
 *
 * (C) Copyright 2019-2023 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various funtions
 * for building the keysas-out binary.
 */

#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unstable_features)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![forbid(private_in_public)]
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![feature(unix_socket_ancillary_data)]

use anyhow::Result;
use clap::{arg, crate_version, Command};
use keysas_lib::init_logger;
use sha2::{Digest, Sha256};
use std::fs::{File, metadata};
use std::io::{IoSliceMut, IoSlice, BufReader, Read};
use std::os::fd::FromRawFd;
use std::os::unix::net::{AncillaryData, SocketAncillary, UnixStream, Messages, UnixListener};
use std::str;
use std::process;

#[macro_use]
extern crate serde_derive;

#[derive(Deserialize, Debug)]
struct InputMetadata {
    filename: String,
    digest: String,
}

#[derive(Serialize, Debug)]
struct FileMetadata {
    filename: String,
    digest: String,
    is_digest_ok: bool,
    is_toobig: bool,
    is_forbidden: bool,
    av_pass: bool,
    yara_pass: bool,    
}

#[derive(Debug)]
struct FileData {
    fd: i32,
    md: FileMetadata,
}

/// Daemon configuration arguments
struct Configuration {
    path_in: String, // path for the socket with keysas-in
    path_out: String, // path for the socket with keysas-out
    max_size: u64 // Maximum size for files
}

/// This function parse the command arguments into a structure
fn parse_args() -> Configuration {
    let matches = Command::new("keysas-out")
        .version(crate_version!())
        .author("Stephane N.")
        .about("keysas-transit, perform file sanitazation.")
        .arg(
            arg!( -i --socket_in <PATH> "Sets a custom socket path for input files").default_value("/run/keysas/sock_in"),
        )
        .arg(
            arg!( -o --socket_out <PATH> "Sets a custom socket path for output files").default_value("/run/keysas/sock_out"),
        )
        .arg(
            arg!( -s --max_size <PATH> "Maximum size for files").default_value("500000000"),
        )
        .get_matches();

    // Unwrap should not panic with default values
    Configuration {
        path_in: matches.get_one::<String>("socket_in").unwrap().to_string(), 
        path_out: matches.get_one::<String>("socket_out").unwrap().to_string(),
        max_size: *matches.get_one::<u64>("max_size").unwrap()
    }
}

/// This function retrieves the file descriptors and metadata from the messages
fn parse_messages(messages: Messages, buffer: &[u8]) -> Vec<FileData> {
    messages.filter_map(|m| {
                //Desencapsulate Result
                match m {
                    Ok(ad) => Some(ad),
                    Err(e) => {
                        log::warn!("failed to get ancillary data: {:?}", e);
                        None
                    }
                }
            })
            .filter_map(|ad| {
                // Filter AncillaryData to keep only ScmRights
                match ad {
                    AncillaryData::ScmRights(scm_rights) => Some(scm_rights),
                    AncillaryData::ScmCredentials(_) => None
                }
            })
            .flatten()
            .filter_map(|fd| {
                // Deserialize metadata
                match bincode::deserialize_from::<&[u8], InputMetadata>(buffer) {
                    Ok(meta) => {
                        // Initialize with failed value by default
                        Some(FileData {
                            fd,
                            md: FileMetadata {
                                filename: meta.filename,
                                digest: meta.digest,
                                is_digest_ok: false,
                                is_toobig: true,
                                is_forbidden: true,
                                av_pass: false,
                                yara_pass: false,
                            },
                        })
                    },
                    Err(e) => {
                        log::warn!("Failed to deserialize messge from in: {e}");
                        None
                    }
                }
            }).collect()
}

fn sha256_digest(file: &File) -> Result<String> {
    let mut reader = BufReader::new(file);

    let digest = {
        let mut hasher = Sha256::new();
        let mut buffer = [0; 1048576];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        hasher.finalize()
    };
    Ok(format!("{:x}", digest))
}

fn check_files(files: &mut Vec<FileData>, conf: &Configuration) {
    for f in files {
        let file = unsafe {File::from_raw_fd(f.fd)};

        // Check digest
        match sha256_digest(&file) {
            Ok(d) => {
                f.md.is_digest_ok = f.md.digest.eq(&d);
            },
            Err(e) => {
                log::warn!("Failed to calculate digest for file {}, error {e}", f.md.filename);
            }
        }

        // Check size
        match metadata(&f.md.filename) {
            Ok(meta) => {
                f.md.is_toobig = meta.len().gt(&conf.max_size);
            },
            Err(e) => {
                log::warn!("Failed to get metadata of file {} error {e}", f.md.filename);
            }
        }

        // TODO Check extension

        // TODO Check anti-virus

        // TODO Check yara rules
    }
}

fn send_files(files: &Vec<FileData>, stream: &UnixStream) {
    for file in files {
        // Get metadata
        let data = match bincode::serialize(&file.md) {
            Ok(d) => d,
            Err(e) => {
                println!("Failed to serialize: {e}");
                process::exit(1);
            }
        };
        let bufs = &[
            IoSlice::new(&data[..])
        ];

        // Send them on the socket
        let mut ancillary_buffer = [0; 4096];
        let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
        ancillary.add_fds(&[file.fd][..]);
        match stream.send_vectored_with_ancillary(&bufs[..], &mut ancillary) {
            Ok(_) => println!("File sent"),
            Err(e) => println!("Failed to send file {e}")
        }
    }
}

fn main() -> Result<()> {
    // TODO activate seccomp

    // Parse command arguments
    let config = parse_args();

    // Configure logger
    init_logger();

    // Open socket with keysas-in
    let sock_in = match UnixStream::connect(&config.path_in) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open socket with keysas-in {e}");
            process::exit(1);
        }
    };

    // Open socket with keysas-out
    let sock_out = match UnixListener::bind(&config.path_out) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open socket with keysas-out {e}");
            process::exit(1);
        }
    };

    // Wait to be connected with keysas-out before starting to accept files in
    let (out_stream, _sck_addr) = match sock_out.accept() {
        Ok(r) => r,
        Err(e) => {
            println!("Failed to accept connection: {e}");
            process::exit(1);
        }
    };

    // Allocate buffers for input messages
    let mut ancillary_buffer_in = [0; 128];
    let mut ancillary_in = SocketAncillary::new(&mut ancillary_buffer_in[..]);

    // Main loop
    // 1. receive file descriptors from in
    // 2. run check on the file
    // 3. send fd and report to out
    loop {
        // 4128 => filename max 4096 bytes and digest 32 bytes
        let mut buf_in = [0; 4128];
        let bufs_in = &mut [IoSliceMut::new(&mut buf_in[..])][..];

        // Listen for message on socket
        match sock_in.recv_vectored_with_ancillary(bufs_in, &mut ancillary_in) {
            Ok(_) => (),
            Err(e) => {
                log::warn!("Failed to receive fds from in: {e}");
                process::exit(1);
            }
        }

        // Parse messages received
        let mut files = parse_messages(ancillary_in.messages(), &buf_in);

        // Run check on message received
        check_files(&mut files, &config);

        // Send fd and report to out
        send_files(&files, &out_stream)
    }
}
