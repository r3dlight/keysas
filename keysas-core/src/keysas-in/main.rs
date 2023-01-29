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
#![feature(unix_socket_abstract)]
#![feature(tcp_quickack)]

use anyhow::{Context, Result};
use bincode::serialize;
use clap::{crate_version, Arg, ArgAction, Command};
use itertools::MultiUnzip;
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus, ABI,
};
use log::{debug, error, info, warn};
use nix::unistd::unlinkat;
use nix::unistd::UnlinkatFlags;
use regex::Regex;
use std::ffi::OsStr;
use std::fs::remove_file;
use std::fs::File;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, SocketAncillary, UnixListener, UnixStream};
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::thread as main_thread;
use std::time::Duration;

#[macro_use]
extern crate serde_derive;
use keysas_lib::{convert_ioslice, init_logger, list_files, sha256_digest};

const CONFIG_DIRECTORY: &str = "/etc/keysas";

#[derive(Serialize, Debug, Clone)]
struct Message {
    filename: Box<OsStr>,
    digest: String,
}

struct Config {
    sas_in: String,
    socket_in: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sas_in: "/var/local/in/".to_string(),
            socket_in: "/run/keysas/socket_in".to_string(),
        }
    }
}
fn landlock_sandbox(socket_in: &str, sas_in: &String) -> Result<(), RulesetError> {
    let abi = ABI::V2;
    let status = Ruleset::new()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        // Read-only access.
        .add_rules(path_beneath_rules(
            &[CONFIG_DIRECTORY, sas_in],
            AccessFs::from_read(abi),
        ))?
        // Read-write access.
        .add_rules(path_beneath_rules(&[socket_in], AccessFs::from_all(abi)))?
        .restrict_self()?;
    match status.ruleset {
        // The FullyEnforced case must be tested.
        RulesetStatus::FullyEnforced => info!("Keysas-in is now fully sandboxed using Landlock !"),
        RulesetStatus::PartiallyEnforced => {
            warn!("Keysas-in is only partially sandboxed using Landlock !")
        }
        // Users should be warned that they are not protected.
        RulesetStatus::NotEnforced => {
            warn!("Keysas-in: Not sandboxed with Landlock ! Please update your kernel.")
        }
    }
    Ok(())
}

fn command_args(config: &mut Config) {
    let matches = Command::new("keysas-in")
        .version(crate_version!())
        .author("Stephane N.")
        .about("keysas-in, input SAS.")
        .arg(
            Arg::new("sas_in")
                .short('i')
                .long("sas_in")
                .value_name("Sets path for incoming directory")
                .default_value("/var/local/in/")
                .action(ArgAction::Set)
                .help("Path for incoming SAS"),
        )
        .arg(
            Arg::new("socket_in")
                .short('s')
                .long("socket_in")
                .value_name("<NAMESPACE>")
                .default_value("socket_in")
                .action(ArgAction::Set)
                .help("Namespace for in-transit abstract socket"),
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
    if let Some(p) = matches.get_one::<String>("socket_in") {
        config.socket_in = p.to_string();
    }
}

fn send_files(files: &[String], stream: &UnixStream, sas_in: &String) -> Result<()> {
    //Remove any file starting by .(dot)
    let re = Regex::new(r"^\.([a-z])*")?;
    let mut files = files.to_owned();
    files.retain(|x| !re.is_match(x));
    //Max X files per send in .chunks(X)
    for batch in files.chunks(2) {
        let (bufs, fhs, fs): (Vec<Vec<u8>>, Vec<File>, Vec<PathBuf>) = batch
            .iter()
            .map(|f| {
                let mut base_path = PathBuf::from(&sas_in);
                base_path.push(f);
                base_path
            })
            .filter_map(|f| {
                // FD is opened in read-only mode
                let fh = match File::open(&f) {
                    Ok(f) => f,
                    Err(e) => {
                        error!("Failed to open file {}: {e}", f.display());
                        process::exit(1);
                    }
                };
                let digest = match sha256_digest(&fh) {
                    Ok(d) => d,
                    Err(e) => {
                        error!("Failed to compute hash {e}");
                        return None;
                    }
                };
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
                Some((data, fh, f))
            })
            .multiunzip();

        let (ios, fds) = convert_ioslice(&fhs, &bufs);

        let mut ancillary_buffer = [0; 4096];
        let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);
        ancillary.add_fds(&fds[..]);
        match stream.send_vectored_with_ancillary(&ios[..], &mut ancillary) {
            Ok(_) => {
                debug!("Chunk of file descriptors is sent");
            }
            Err(e) => error!("Failed to send fds: {e}"),
        }
        // Files are unlinked once fds are sent
        for it in fs.iter().zip(fds.iter()) {
            let (file_path, fd) = it;
            match unlinkat(Some(*fd), file_path, UnlinkatFlags::NoRemoveDir) {
                Ok(_) => info!("File {:?} is now removed.", file_path),
                Err(e) => error!("Cannot unlink file {:?}: {:?}", file_path, e),
            };
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    // TODO:
    // - Add seccomp whitelist
    // - Check that fd is not dir

    let mut config = Config::default();
    command_args(&mut config);
    let socket = Path::new(&config.socket_in);
    init_logger();
    match socket.parent() {
        Some(parent) => landlock_sandbox(parent.to_str().unwrap(), &config.sas_in)?,
        None => {
            error!("Failed to find parent directory for socket");
            process::exit(1);
        }
    }
    info!("Keysas-in started :)");
    info!("Running configuration is:");
    info!("- socket_in: {}", &config.socket_in);
    info!("- sas_in: {}", &config.sas_in);
    if Path::new(&config.socket_in).exists() {
        match remove_file(&config.socket_in) {
            Ok(_) => debug!("Removing previously created socket_in"),
            Err(why) => {
                error!("Cannot remove previously created socket_in: {:?}", why);
                process::exit(1);
            }
        }
    }
    let addr = SocketAddr::from_abstract_namespace(config.socket_in)?;
    let sock = match UnixListener::bind_addr(addr) {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to create abstract socket: {e}");
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
