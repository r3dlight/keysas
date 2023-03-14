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
use anyhow::{Context, Result};
use clap::{crate_version, Arg, ArgAction, Command};
use keysas_lib::append_ext;
use keysas_lib::init_logger;
use keysas_lib::sha256_digest;
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus, ABI,
};
use log::{error, info, warn};
use nix::unistd;
use openssl::nid::Nid;
use openssl::x509::X509;
use oqs::sig::Signature;
use sha2::Digest;
use sha2::Sha256;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::BufReader;
use std::io::{BufWriter, IoSliceMut, Write};
use std::os::fd::FromRawFd;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{AncillaryData, Messages, SocketAddr, SocketAncillary, UnixStream};
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::str;
use time::OffsetDateTime;

#[macro_use]
extern crate serde_derive;

#[derive(Serialize, Deserialize, Debug, Clone)]
struct FileMetadata {
    filename: String,
    digest: String,
    is_digest_ok: bool,
    is_toobig: bool,
    size: u64,
    is_type_allowed: bool,
    av_pass: bool,
    av_report: Vec<String>,
    yara_pass: bool,
    yara_report: String, // this should be a vec
    timestamp: String,
    is_corrupted: bool,
    file_type: String,
}

#[derive(Debug)]
struct FileData {
    fd: i32,
    md: FileMetadata,
}
#[derive(Serialize, Deserialize, Clone)]
struct MetaData {
    station_id: String,
    name: String,
    date: String,
    file_type: String,
    is_valid: bool,
    report: FileReport,
}

#[derive(Serialize, Deserialize, Clone)]
struct Bd {
    file_digest: String,
    metadata_digest: String,
    station_certificate: String,
    file_signature: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Report {
    metadata: MetaData,
    binding: Bd,
}

#[derive(Serialize, Deserialize, Clone)]
struct FileReport {
    yara: String,
    av: Vec<String>,
    type_allowed: bool,
    size: u64,
    corrupted: bool,
    toobig: bool,
}

/// Daemon configuration arguments
struct Configuration {
    socket_out: String, // Path for the socket with keysas-transit
    sas_out: String,    // Path to output directory
    yara_clean: bool,
    signing_cert: String,
    signing_key: String,
}

const CONFIG_DIRECTORY: &str = "/etc/keysas";

fn landlock_sandbox(sas_out: &String) -> Result<(), RulesetError> {
    let abi = ABI::V2;
    let status = Ruleset::new()
        .handle_access(AccessFs::from_all(abi))?
        .create()?
        // Read-only access.
        .add_rules(path_beneath_rules(
            &[CONFIG_DIRECTORY],
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
        .arg(
            Arg::new("yara_clean")
                .short('c')
                .long("yara_clean")
                .action(clap::ArgAction::SetTrue)
                .help("Remove the file if a Yara rule matched"),
        )
        .arg(
            Arg::new("signing_cert")
                .short('p')
                .long("signing_cert")
                .default_value("/etc/keysas/file-sign.pem")
                .action(clap::ArgAction::Set)
                .help("Path to signing PEM certificat (must be imported and signed)"),
        )
        .arg(
            Arg::new("signing_key")
                .short('s')
                .long("signing_key")
                .default_value("/etc/keysas/file-sign.key")
                .action(clap::ArgAction::Set)
                .help("Path to secret signing key"),
        )
        .arg(
            Arg::new("version")
                .short('v')
                .long("version")
                .action(ArgAction::Version)
                .help("Print the version and exit"),
        )
        .get_matches();

    // Unwrap should not panic with default values
    Configuration {
        socket_out: matches.get_one::<String>("socket_out").unwrap().to_string(),
        sas_out: matches.get_one::<String>("sas_out").unwrap().to_string(),
        yara_clean: matches.get_flag("yara_clean"),
        signing_cert: matches
            .get_one::<String>("signing_cert")
            .unwrap()
            .to_string(),
        signing_key: matches
            .get_one::<String>("signing_key")
            .unwrap()
            .to_string(),
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
                    warn!("Failed to deserialize messge from keysas-transit: {e}, killing myself.");
                    process::exit(1);
                }
            }
        })
        .collect()
}

fn get_x509_subject(cert_file: Vec<u8>) -> Result<String> {
    let cert = X509::from_pem(&cert_file)?;
    match cert.subject_name().entries_by_nid(Nid::COMMONNAME).next() {
        Some(subject) => {
            return Ok(subject.data().as_utf8()?.to_string());
        }
        None => {
            error!("Cannot convert subject.data as UTF8");
            return Ok("".to_string());
        }
    }
}

fn pq_sign(file: &File, secret_pq_key: &str) -> Result<Option<Signature>> {
    // Important: initialize liboqs
    oqs::init();
    let scheme = oqs::sig::Sig::new(oqs::sig::Algorithm::SphincsSha256256fRobust)
        .with_context(|| "Unable to create new signature scheme")?;

    if Path::new(secret_pq_key).exists() && Path::new(secret_pq_key).is_file() {
        let sig_sk_bytes =
            std::fs::read(secret_pq_key).with_context(|| "Unable to read secret file")?;
        //TODO: fix this unwrap()
        let tmp_sig_sk = oqs::sig::Sig::secret_key_from_bytes(&scheme, &sig_sk_bytes).unwrap();
        let sig_sk = tmp_sig_sk.to_owned();
        // Read the file
        let mut contents = Vec::new();
        let mut file_clone = file.try_clone()?;
        file_clone.read_to_end(&mut contents)?;
        //let contents = std::fs::read(f).with_context(|| "Unable to read file to sign")?;
        // get the signature
        let signature = scheme
            .sign(&contents, &sig_sk)
            .with_context(|| "Unable to create signature")?;
        Ok(Some(signature))
    } else {
        log::warn!("No signature was created.");
        Ok(None)
    }
}

/// This function output files and report received from transit
/// The function first check the digest of the file received
fn output_files(files: Vec<FileData>, conf: &Configuration) -> Result<()> {
    for mut f in files {
        let file = unsafe { File::from_raw_fd(f.fd) };
        // Position the cursor at the beginning of the file
        match unistd::lseek(f.fd, 0, nix::unistd::Whence::SeekSet) {
            Ok(_) => (),
            Err(e) => {
                error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                process::exit(1);
            }
        }
        // Check digest
        let digest = match sha256_digest(&file) {
            Ok(d) => d,
            Err(e) => {
                error!(
                    "Failed to calculate digest for file {}: {e}, killing myself.",
                    f.md.filename
                );
                process::exit(1);
            }
        };

        // Test if digest is correct
        if digest.ne(&f.md.digest) {
            warn!("Digest invalid for file {}", f.md.filename);
            f.md.is_digest_ok = false;
        }
        // Always Write a report to json format
        let mut path = PathBuf::new();
        path.push(conf.sas_out.clone());
        path.push(&f.md.filename);
        let path = append_ext("krp", path);
        let mut report = match File::options()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
        {
            Ok(f) => {
                info!("Writing a report on path: {}", path.display());
                f
            }
            Err(e) => {
                error!(
                    "Failed to create report for file {}: {e}, killing myself.",
                    f.md.filename
                );
                process::exit(1);
            }
        };
        let timestamp = format!(
            "{}-{}-{}_{}-{}-{}-{}",
            OffsetDateTime::now_utc().day(),
            OffsetDateTime::now_utc().month(),
            OffsetDateTime::now_utc().year(),
            OffsetDateTime::now_utc().hour(),
            OffsetDateTime::now_utc().minute(),
            OffsetDateTime::now_utc().second(),
            OffsetDateTime::now_utc().nanosecond()
        );

        let new_file_report = FileReport {
            yara: f.md.yara_report.clone(),
            av: f.md.av_report.clone(),
            type_allowed: f.md.is_type_allowed,
            size: f.md.size,
            corrupted: f.md.is_corrupted,
            toobig: f.md.is_toobig,
        };

        let mut subject_utf8 = String::new();
        let mut cert_file = Vec::new();
        // Get data from pem cert located in /etc/keysas
        if Path::new(&conf.signing_cert).exists() && Path::new(&conf.signing_cert).is_file() {
            cert_file = match std::fs::read(&conf.signing_cert) {
                Ok(cert_file) => cert_file,
                Err(e) => {
                    error!("Cannot read certificate: {e}");
                    continue;
                }
            };

            subject_utf8 = match get_x509_subject(cert_file.clone()) {
                Ok(subject) => subject,
                Err(e) => {
                    error!("{e}");
                    //If no subject return an empty string
                    "".to_string()
                }
            };
        }

        let new_metadata = MetaData {
            station_id: subject_utf8.to_string(),
            name: f.md.filename.clone(),
            date: timestamp,
            file_type: f.md.file_type.clone(),
            is_valid: f.md.av_pass
                && f.md.yara_pass
                && !f.md.is_toobig
                && !f.md.is_corrupted
                && f.md.is_digest_ok
                && f.md.is_type_allowed,
            report: new_file_report,
        };
        let json_string = serde_json::to_string_pretty(&new_metadata)?;
        let mut hasher = Sha256::new();
        hasher.update(json_string.as_bytes());
        let result = hasher.finalize();
        let meta_digest = format!("{result:x}");
        match unistd::lseek(f.fd, 0, nix::unistd::Whence::SeekSet) {
            Ok(_) => (),
            Err(e) => {
                error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                process::exit(1);
            }
        }

        let mut signature = String::new();
        if Path::new(&conf.signing_key).is_file() {
            let opt_signature = match pq_sign(&file, &conf.signing_key) {
                Ok(signature) => signature,
                Err(e) => {
                    error!("Secret signing key is present but unable to sign on file descriptor: {e:?}, killing myself.");
                    process::exit(1);
                }
            };
            signature = match opt_signature {
                Some(signature) => std::str::from_utf8(signature.as_ref())?.to_string(),
                None => {
                    log::error!("Cannot get signature from utf8.");
                    String::new()
                }
            };
        }

        let new_bd = Bd {
            file_digest: f.md.digest.clone(),
            metadata_digest: meta_digest,
            station_certificate: String::from_utf8(cert_file)?,
            file_signature: signature,
        };
        let new_report = Report {
            metadata: new_metadata,
            binding: new_bd,
        };

        let json_report = match serde_json::to_string_pretty(&new_report) {
            Ok(j) => j,
            Err(e) => {
                error!("Cannot serialize MetaData struct to json for writing report: {e:?}, killing myself.");
                process::exit(1);
            }
        };

        match writeln!(report, "{}", json_report) {
            Ok(_) => (),
            Err(e) => {
                error!(
                    "Failed to write report for file {}: {e}, killing myself.",
                    f.md.filename
                );
                process::exit(1);
            }
        }

        // Test if the check passed, if yes write the file to sas_out
        if f.md.is_digest_ok
            && !f.md.is_toobig
            && f.md.is_type_allowed
            && f.md.av_pass
            && !f.md.is_corrupted
            && (f.md.yara_pass || (!f.md.yara_pass && !conf.yara_clean))
        {
            // Output file
            let mut reader = BufReader::new(&file);

            let mut path = PathBuf::new();
            path.push(&conf.sas_out);
            path.push(&f.md.filename);
            let output = match File::options().write(true).create(true).open(path) {
                Ok(f) => f,
                Err(e) => {
                    error!(
                        "Failed to create output file {}: {e}, killing myself.",
                        f.md.filename
                    );
                    process::exit(1);
                }
            };
            // Position the cursor at the beginning of the file
            match unistd::lseek(f.fd, 0, nix::unistd::Whence::SeekSet) {
                Ok(_) => (),
                Err(e) => {
                    error!("Unable to lseek on file descriptor: {e:?}, killing myself.");
                    process::exit(1);
                }
            }
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
    Ok(())
}

fn main() -> Result<()> {
    // TODO activate seccomp

    // Parse command arguments
    let config = parse_args();

    // Configure logger
    init_logger();

    //Init Landlock
    landlock_sandbox(&config.sas_out)?;

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
        output_files(files, &config)?;
    }
}
