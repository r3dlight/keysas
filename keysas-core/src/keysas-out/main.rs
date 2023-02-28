// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-out".
 *
 * (C) Copyright 2019-2023 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various funtions
 * for building the keysas-out binary.
 */

#![feature(unix_socket_ancillary_data)]
#![feature(unix_socket_abstract)]
#![feature(tcp_quickack)]
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
#[warn(unused_imports)]
use anyhow::Result;
use clap::{crate_version, Arg, ArgAction, Command};
use keysas_lib::init_logger;
use keysas_lib::sha256_digest;
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus, ABI,
};
use log::{error, info, warn};
use nix::unistd;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::{BufWriter, IoSliceMut, Write};
use std::os::fd::FromRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{AncillaryData, Messages, SocketAddr, SocketAncillary, UnixStream};
use std::path::PathBuf;
use std::process;
use std::str;

#[macro_use]
extern crate serde_derive;

#[derive(Deserialize, Debug)]
struct FileMetadata {
    filename: String,
    digest: String,
    is_digest_ok: bool,
    is_toobig: bool,
    is_type_allowed: bool,
    av_pass: bool,
    av_report: Vec<String>,
    yara_pass: bool,
    yara_report: String,
}

#[derive(Debug)]
struct FileData {
    fd: i32,
    md: FileMetadata,
}

/// Daemon configuration arguments
struct Configuration {
    socket_out: String, // Path for the socket with keysas-transit
    sas_out: String,    // Path to output directory
}

const CONFIG_DIRECTORY: &str = "/etc/keysas";

fn landlock_sandbox(socket_out: &String, sas_out: &String) -> Result<(), RulesetError> {
    let abi = ABI::V2;
    let status = Ruleset::new()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        // Read-only access.
        .add_rules(path_beneath_rules(
            &[CONFIG_DIRECTORY, socket_out],
            AccessFs::from_read(abi),
        ))?
        // Read-write access.
        .add_rules(path_beneath_rules(&[sas_out], AccessFs::from_all(abi)))?
        .restrict_self()?;
    match status.ruleset {
        // The FullyEnforced case must be tested.
        RulesetStatus::FullyEnforced => {
            info!("Keysas-out is now fully sandboxed using Landlock !")
        }
        RulesetStatus::PartiallyEnforced => {
            warn!("Keysas-out is only partially sandboxed using Landlock !")
        }
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => {
            warn!("Keysas-out: Not sandboxed with Landlock ! Please update your kernel.")
        }
    }
    Ok(())
}

/// This function parse the command arguments into a structure
fn parse_args() -> Configuration {
    let matches = Command::new("keysas-out")
        .version(crate_version!())
        .author("Stephane N.")
        .about("keysas-out, perform file and report write back.")
        .arg(
            Arg::new("socket_out")
                .short('o')
                .long("socket_out")
                .value_name("<NAMESPACE>")
                .default_value("socket_out")
                .action(ArgAction::Set)
                .help("Sets a custom abstract socket for files coming from transit"),
        )
        .arg(
            Arg::new("sas_out")
                .short('g')
                .long("sas_out")
                .value_name("<PATH>")
                .default_value("/var/local/out")
                .action(ArgAction::Set)
                .help("Sets the out sas path for transfering files"),
        )
        .get_matches();

    // Unwrap should not panic with default values
    Configuration {
        socket_out: matches.get_one::<String>("socket_out").unwrap().to_string(),
        sas_out: matches.get_one::<String>("sas_out").unwrap().to_string(),
    }
}

/// This function retrieves the file descriptors and metadata from the messages
fn parse_messages(messages: Messages, buffer: &[u8]) -> Vec<FileData> {
    messages
        .filter_map(|m| {
            //Desencapsulate Result
            match m {
                Ok(ad) => Some(ad),
                Err(e) => {
                    warn!("failed to get ancillary data: {:?}", e);
                    None
                }
            }
        })
        .filter_map(|ad| {
            // Filter AncillaryData to keep only ScmRights
            match ad {
                AncillaryData::ScmRights(scm_rights) => Some(scm_rights),
                AncillaryData::ScmCredentials(_) => None,
            }
        })
        .flatten()
        .filter_map(|fd| {
            // Deserialize metadata
            match bincode::deserialize_from::<&[u8], FileMetadata>(buffer) {
                Ok(meta) => Some(FileData { fd, md: meta }),
                Err(e) => {
                    warn!("Failed to deserialize messge from in: {e}");
                    None
                }
            }
        })
        .collect()
}

/// This function output files and report received from transit
/// The function first check the digest of the file received
fn output_files(files: Vec<FileData>, conf: &Configuration) {
    for mut f in files {
        let file = unsafe { File::from_raw_fd(f.fd) };
        // Position the cursor at the beginning of the file
        unistd::lseek(f.fd, 0, nix::unistd::Whence::SeekSet).unwrap();
        // Check digest
        let digest = match sha256_digest(&file) {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    "Failed to calculate digest for file {}, error {e}",
                    f.md.filename
                );
                continue;
            }
        };
        // Test if digest is correct
        if digest.ne(&f.md.digest) {
            warn!("Digest invalid for file {}", f.md.filename);
            f.md.is_digest_ok = false;
        }

        // Test if the check passed, if not write a report
        if !f.md.is_digest_ok
            || f.md.is_toobig
            || !f.md.is_type_allowed
            || !f.md.av_pass
            || !f.md.yara_pass
        {
            // Checks have failed writing a report
            let mut path = PathBuf::new();
            path.push(conf.sas_out.clone());
            path.push(&f.md.filename);
            path.set_extension("report");
            let mut report = match File::options()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(f) => f,
                Err(e) => {
                    error!(
                        "Failed to create report for file {}, error {e}",
                        f.md.filename
                    );
                    continue;
                }
            };

            if !f.md.is_digest_ok {
                match writeln!(report, "Invalid hash - original hash is {}", f.md.digest) {
                    Ok(_) => (),
                    Err(e) => {
                        error!(
                            "Failed to write report for file {}, error {e}",
                            f.md.filename
                        );
                        continue;
                    }
                }
            }

            if f.md.is_toobig {
                match writeln!(report, "File was too big") {
                    Ok(_) => (),
                    Err(e) => {
                        error!(
                            "Failed to write report for file {}, error {e}",
                            f.md.filename
                        );
                        continue;
                    }
                }
            }

            if !f.md.is_type_allowed {
                match writeln!(report, "File extension is forbidden") {
                    Ok(_) => (),
                    Err(e) => {
                        error!(
                            "Failed to write report for file {}, error {e}",
                            f.md.filename
                        );
                        continue;
                    }
                }
            }

            if !f.md.av_pass {
                match writeln!(report, "Clam : {:?}", f.md.av_report) {
                    Ok(_) => (),
                    Err(e) => {
                        error!(
                            "Failed to write report for file {}, error {e}",
                            f.md.filename
                        );
                        continue;
                    }
                }
            }

            if !f.md.yara_pass {
                match writeln!(report, "Yara : {}", f.md.yara_report) {
                    Ok(_) => (),
                    Err(e) => {
                        error!(
                            "Failed to write report for file {}, error {e}",
                            f.md.filename
                        );
                        continue;
                    }
                }
            }
        } else {
            // Output file
            let mut reader = BufReader::new(&file);

            let mut path = PathBuf::new();
            path.push(&conf.sas_out);
            path.push(&f.md.filename);
            let output = match File::options().write(true).create_new(true).open(path) {
                Ok(f) => f,
                Err(e) => {
                    error!("Failed to create output file {}, error {e}", f.md.filename);
                    continue;
                }
            };
            // Position the cursor at the beginning of the file
            unistd::lseek(f.fd, 0, nix::unistd::Whence::SeekSet).unwrap();
            let mut writer = BufWriter::new(output);
            match io::copy(&mut reader, &mut writer) {
                Ok(_) => (),
                Err(e) => {
                    error!("Failed to output file {}, error {e}", f.md.filename);
                }
            }
        }
        drop(file);
    }
}

fn main() -> Result<()> {
    // TODO activate seccomp

    // Parse command arguments
    let config = parse_args();

    // Configure logger
    init_logger();

    //Init Landlock
    landlock_sandbox(&config.socket_out, &config.sas_out)?;

    // Open socket with keysas-transit
    let addr_out = SocketAddr::from_abstract_name(&config.socket_out)?;
    let sock_out = match UnixStream::connect_addr(&addr_out) {
        Ok(s) => {
            info!("Connected to keysas-transit socket.");
            s
        }
        Err(e) => {
            error!("Failed to open abstract socket with keysas-transit {e}");
            process::exit(1);
        }
    };

    // Allocate buffers for input messages
    let mut ancillary_buffer_in = [0; 128];
    let mut ancillary_in = SocketAncillary::new(&mut ancillary_buffer_in[..]);

    // Main loop
    // 1. receive file descriptor and metadata from transit
    // 2. Write file and report to output
    loop {
        // 4128 => filename max 4096 bytes and digest 32 bytes
        let mut buf_in = [0; 4128];
        let bufs_in = &mut [IoSliceMut::new(&mut buf_in[..])][..];

        // Listen for message on socket
        match sock_out.recv_vectored_with_ancillary(bufs_in, &mut ancillary_in) {
            Ok(_) => (),
            Err(e) => {
                warn!("Failed to receive fds from in: {e}");
                process::exit(1);
            }
        }

        // Parse messages received
        let files = parse_messages(ancillary_in.messages(), &buf_in);

        // Output file
        output_files(files, &config);
    }
}
