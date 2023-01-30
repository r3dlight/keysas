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

use anyhow::Result;
use clam_client::{client::ClamClient, response::ClamScanResult};
use clap::{crate_version, Arg, ArgAction, Command};
use infer::get_from_path;
use keysas_lib::init_logger;
use keysas_lib::sha256_digest;
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus, ABI,
};
use log::{error, info, warn};
use std::fs::{metadata, File};
use std::io::{IoSlice, IoSliceMut};
use std::net::IpAddr;
use std::os::fd::FromRawFd;
use std::os::unix::net::{
    AncillaryData, Messages, SocketAddr, SocketAncillary, UnixListener, UnixStream,
};
use std::path::Path;
use std::process;
use std::str;
use std::thread as main_thread;
use std::time::Duration;
use yara::*;

const CONFIG_DIRECTORY: &str = "/etc/keysas";

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
    is_type_allowed: bool,
    av_pass: bool,
    av_report: String,
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
    socket_in: String,               // path for the socket with keysas-in
    socket_out: String,              // path for the socket with keysas-out
    max_size: u64,                   // Maximum size for files
    magic_list: Vec<String>,         // List of allowed file type
    clamav_ip: String,               // ClamAV IP address
    clamav_port: u16,                // ClamAV port number
    clam_client: Option<ClamClient>, // Client for clamd
    rule_path: String,               // Path to yara rules
    yara_timeout: i32,               // Timeout for yara
    yara_rules: Option<Rules>,       // Yara rules
}

fn landlock_sandbox(
    socket_in: &String,
    socket_out: &String,
    rule_path: &String,
) -> Result<(), RulesetError> {
    let abi = ABI::V2;
    let status = Ruleset::new()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        // Read-only access.
        .add_rules(path_beneath_rules(
            &[CONFIG_DIRECTORY, socket_in, rule_path],
            AccessFs::from_read(abi),
        ))?
        // Read-write access.
        .add_rules(path_beneath_rules(
            &[socket_out, "/run/keysas"],
            AccessFs::from_all(abi),
        ))?
        .restrict_self()?;
    match status.ruleset {
        // The FullyEnforced case must be tested.
        RulesetStatus::FullyEnforced => {
            info!("Keysas-transit is now fully sandboxed using Landlock !")
        }
        RulesetStatus::PartiallyEnforced => {
            warn!("Keysas-transit is only partially sandboxed using Landlock !")
        }
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => {
            warn!("Keysas-transit: Not sandboxed with Landlock ! Please update your kernel.")
        }
    }
    Ok(())
}

/// This function parse the command arguments into a structure
fn parse_args() -> Configuration {
    let matches = Command::new("keysas-transit")
          .version(crate_version!())
          .author("Stephane N.")
          .about("keysas-transit, perform file sanitization.")
          .arg(
             Arg::new("socket_in")
                 .short('i')
                 .long("socket_in")
                 .value_name("<NAMESPACE>")
                 .default_value("socket_in")
                 .action(ArgAction::Set)
                 .help("Sets a custom abstract socket for input files"),
         )
         .arg(
             Arg::new("socket_out")
                 .short('o')
                 .long("socket_out")
                 .value_name("<NAMESPACE>")
                 .default_value("socket_out")
                 .action(ArgAction::Set)
                 .help("Sets a custom abstract socket for output files"),
         )
         .arg(
             Arg::new("max_size")
                 .short('s')
                 .long("max_size")
                 .value_name("<SIZE_IN_BYTES>")
                 .default_value("500000000")
                 .action(ArgAction::Set)
                 .value_parser(clap::value_parser!(u64))
                 .help("Maximum size for files"),
         )
         .arg(
             Arg::new("allowed_formats")
                 .short('a')
                 .long("allowed_formats")
                 .value_name("<LIST>")
                 .default_value("jpg,png,gif,bmp,mp4,m4v,avi,wmv,mpg,flv,mp3,wav,ogg,epub,mobi,doc,docx,xls,xlsx,ppt,pptx")
                 .action(ArgAction::Set)
                 .help("Whitelist (comma separated) of allowed file formats"),
         )
         .arg(
             Arg::new("clamavip")
                 .short('c')
                 .long("clamavip")
                 .value_name("<IP>")
                 .default_value("127.0.0.1")
                 .action(ArgAction::Set)
                 .help("Clamav IP address"),
         )
         .arg(
             Arg::new("clamavport")
                 .short('p')
                 .long("clamavport")
                 .value_name("<PORT>")
                 .default_value("3310")
                 .action(ArgAction::Set)
                 .value_parser(clap::value_parser!(u16))
                 .help("Clamav port number"),
         )
         .arg(
             Arg::new("rules_path")
                 .short('r')
                 .long("rules_path")
                 .value_name("<PATH>")
                 .default_value("/usr/share/keysas/rules/index.yar")
                 .action(ArgAction::Set)
                 .help("Sets a custom path for Yara rules"),
         )
         .arg(
             Arg::new("yara_timeout")
                 .short('t')
                 .long("yara_timeout")
                 .value_name("<SECONDS>")
                 .default_value("100")
                 .action(ArgAction::Set)
                 .value_parser(clap::value_parser!(i32))
                 .help("Sets a custom timeout for libyara scans"),
         )
          .get_matches();

    // Unwrap should not panic with default values
    Configuration {
        socket_in: matches.get_one::<String>("socket_in").unwrap().to_string(),
        socket_out: matches.get_one::<String>("socket_out").unwrap().to_string(),
        max_size: *matches.get_one::<u64>("max_size").unwrap(),
        magic_list: matches
            .get_one::<String>("allowed_formats")
            .unwrap()
            .split(',')
            .map(String::from)
            .collect(),
        clamav_ip: matches.get_one::<String>("clamavip").unwrap().to_string(),
        clamav_port: *matches.get_one::<u16>("clamavport").unwrap(),
        clam_client: None,
        rule_path: matches.get_one::<String>("rules_path").unwrap().to_string(),
        yara_timeout: *matches.get_one::<i32>("yara_timeout").unwrap(),
        yara_rules: None,
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
                            is_type_allowed: false,
                            av_pass: false,
                            av_report: String::new(),
                            yara_pass: false,
                            yara_report: String::new(),
                        },
                    })
                }
                Err(e) => {
                    warn!("Failed to deserialize messge from in: {e}");
                    None
                }
            }
        })
        .collect()
}

/// This function returns true if the file type is in the list provided
fn check_is_extension_allowed(filename: &String, conf: &Configuration) -> bool {
    match get_from_path(filename) {
        Ok(Some(info)) => conf.magic_list.contains(&info.extension().to_string()),
        Ok(None) => false,
        Err(e) => {
            warn!("Failed to get Mime type for file {} error {e}", filename);
            false
        }
    }
}

/// This function check each file given in the input vector.
/// Checks are made against the provided configuration.
/// Checks performed are:
///     - File digest is correct
///     - File size is less than maximum size provided in configuration
///     - File type is in the list provided in configuration
///     - Anti-virus check
///     - Yara rules check
/// Checks results are marked in file metadata.
/// This function does not modify the files.
fn check_files(files: &mut Vec<FileData>, conf: &Configuration) {
    for f in files {
        let file = unsafe { File::from_raw_fd(f.fd) };

        // Check digest
        match sha256_digest(&file) {
            Ok(d) => {
                f.md.is_digest_ok = f.md.digest.eq(&d);
            }
            Err(e) => {
                warn!(
                    "Failed to calculate digest for file {}, error {e}",
                    f.md.filename
                );
            }
        }

        // Check size
        match metadata(&f.md.filename) {
            Ok(meta) => {
                f.md.is_toobig = meta.len().gt(&conf.max_size);
            }
            Err(e) => {
                warn!("Failed to get metadata of file {} error {e}", f.md.filename);
            }
        }

        // Check extension
        f.md.is_type_allowed = check_is_extension_allowed(&f.md.filename, conf);

        // Check anti-virus
        match &conf.clam_client {
            Some(client) => match client.scan_stream(file) {
                Ok(ClamScanResult::Ok) => {}
                Ok(ClamScanResult::Found(l, v)) => {
                    warn!("Clam found virus {v} at {l}");
                    f.md.av_report
                        .push_str(format!("Clam report: {l} - {v}").as_str());
                    f.md.av_pass = false;
                }
                Ok(ClamScanResult::Error(e)) => {
                    error!("Clam error while scanning file {e}");
                    f.md.av_pass = false;
                }
                Err(e) => {
                    error!("Failed to run clam on file {e}");
                    f.md.av_pass = false;
                }
            },
            None => {
                error!("Clamd client failed");
                f.md.av_pass = false;
            }
        }

        // Check yara rules
        match &conf.yara_rules {
            Some(rules) => match rules.scan_file(Path::new(&f.md.filename), conf.yara_timeout) {
                Ok(results) => match results.is_empty() {
                    true => {
                        f.md.yara_pass = true;
                    }
                    false => {
                        for result in results {
                            f.md.yara_report.push_str(result.identifier);
                        }
                        f.md.yara_pass = false;
                        warn!("Yara rules matched");
                    }
                },
                Err(e) => {
                    error!("Yara cannot scan file {} error {e}", f.md.filename);
                }
            },
            None => {
                error!("Yara rules not present");
                f.md.yara_pass = false;
            }
        }
    }
}

/// This functions send the files filedescriptor and metadata to the socket
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
        let bufs = &[IoSlice::new(&data[..])];

        // Send them on the socket
        let mut ancillary_buffer = [0; 4096];
        let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
        ancillary.add_fds(&[file.fd][..]);
        match stream.send_vectored_with_ancillary(&bufs[..], &mut ancillary) {
            Ok(_) => println!("File sent"),
            Err(e) => println!("Failed to send file {e}"),
        }
    }
}

/// This function returns a client to clamd
fn get_clamd_client(clamav_ip: &str, clamav_port: u16) -> Option<ClamClient> {
    match ClamClient::new_with_timeout(clamav_ip, clamav_port, 5) {
        Ok(client) => match client.version() {
            Ok(version) => {
                info!("Clamd version {:?}", version);
                Some(client)
            }
            Err(e) => {
                error!("Clamd is not responding {e}");
                None
            }
        },
        Err(e) => {
            error!("Failed to contact clamd {e}");
            None
        }
    }
}

fn main() -> Result<()> {
    // TODO activate seccomp

    // Parse command arguments
    let mut config = parse_args();

    // landlock init
    landlock_sandbox(&config.socket_in, &config.socket_out, &config.rule_path)?;

    // Configure logger
    init_logger();

    // Initilize clamd client
    // Test if ClamAV IP is valid
    match config.clamav_ip.parse::<IpAddr>() {
        Ok(_) => (),
        Err(e) => {
            error!("ClamAV invalid IP address {e}");
            process::exit(1);
        }
    }
    // Test if clamd is responding
    config.clam_client = get_clamd_client(&config.clamav_ip, config.clamav_port);
    if config.clam_client.is_none() {
        error!("Failed to get clamd client");
        process::exit(1);
    }

    // Initialize yara rules
    match Compiler::new() {
        Ok(c) => match c.add_rules_file_with_namespace(&config.rule_path, "keysas") {
            Ok(c) => match c.compile_rules() {
                Ok(r) => {
                    info!("Yara compiler initialized.");
                    config.yara_rules = Some(r);
                }
                Err(e) => {
                    error!("Failed to compile yara rules {e}");
                    process::exit(1);
                }
            },
            Err(e) => {
                error!("Failed to add yara rules to compiler {e}");
                process::exit(1);
            }
        },
        Err(e) => {
            error!("Failed to initialize yara compiler {e}");
            process::exit(1);
        }
    };

    // Open socket with keysas-in
    let addr_in = SocketAddr::from_abstract_namespace(config.socket_in)?;
    let sock_in = match UnixStream::connect_addr(&addr_in) {
        Ok(s) => {
            info!("Connected to Keysas-in socket.");
            s
        }
        Err(e) => {
            error!("Failed to open socket with keysas-in {e}");
            process::exit(1);
        }
    };

    // Open socket with keysas-out
    let addr_out = SocketAddr::from_abstract_namespace(config.socket_out)?;
    let sock_out = match UnixListener::bind_addr(&addr_out) {
        Ok(s) => {
            info!("Socket for Keysas-out created.");
            s
        }
        Err(e) => {
            error!("Failed to open socket with keysas-out {e}");
            process::exit(1);
        }
    };

    // Wait to be connected with keysas-out before starting to accept files in
    let (out_stream, _sck_addr) = match sock_out.accept() {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to accept connection: {e}");
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
                warn!("Failed to receive fds from in: {e}");
                process::exit(1);
            }
        }

        // Parse messages received
        let mut files = parse_messages(ancillary_in.messages(), &buf_in);

        // Run check on message received
        check_files(&mut files, &config);

        // Send fd and report to out
        send_files(&files, &out_stream);
        main_thread::sleep(Duration::from_millis(500));
    }
}
