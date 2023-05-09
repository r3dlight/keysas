// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-out".
 *
 * (C) Copyright 2019-2023 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various funtions
 * for building the keysas-out binary.
 */

//! Output daemon
//!
//! Output the files from the processing pipeline into the temporary storage.
//! The daemon also generates a report for the file that contains the result from the checks.
//!
//! The report is JSON file containing the following structure:
//! ```json
//! {
//!     "metadata": {
//!         "name",             // String: File name
//!         "date",             // String DD-MM-YYYY_HH-mm-SS-NN: Date of creation of the report
//!         "file_type",        // String: file type
//!         "is_valid",         // Boolean: true if all checks passed
//!         "report": {
//!             "yara",         // String: yara detailed report
//!             "av",           // String: clamav detailed report
//!             "type_allowed", // Boolean: false if forbidden type detected
//!             "size",         // u64: file size
//!             "corrupted",    // boolean: true if file integrity corruption detected
//!             "toobig"        // Boolean, true file size is too big
//!         }
//!     },
//!     "binding" : {
//!         "file_digest",         // String: base64 encoded SHA256 digest of the file
//!         "metadata_digest",     // String: base64 encoded SHA256 digest of the metadata
//!         "station_certificate", // String: concatenation of the station signing certificates PEM
//!         "report_signature",    // String: base64 encoded concatenation of the ED25519 and Dilithium5 signatures
//!     }
//! }
//! ```
//!
//! The report is signed by the station.

#![feature(unix_socket_ancillary_data)]
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
#![warn(unused_imports)]
#![warn(missing_docs)]
#![feature(str_split_remainder)]

use anyhow::Result;
use base64::{engine::general_purpose, Engine as _};
use clap::{crate_version, Arg, ArgAction, Command};
use keysas_lib::append_ext;
use keysas_lib::init_logger;
use keysas_lib::keysas_hybrid_keypair::HybridKeyPair;
use keysas_lib::keysas_key::KeysasKey;
use keysas_lib::sha256_digest;
use landlock::{
    path_beneath_rules, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetError,
    RulesetStatus, ABI,
};
use log::{error, info, warn};
use nix::unistd;
use pkcs8::der::EncodePem;
use sha2::Digest;
use sha2::Sha256;
use std::fs::File;
use std::io;
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

/// Structure that holds a file metadata
#[derive(Serialize, Deserialize, Debug, Clone)]
struct FileMetadata {
    /// Name of the file
    filename: String,
    /// SHA256 digest of the file
    digest: String,
    /// True if a file corruption as occured during processing
    is_digest_ok: bool,
    /// True if the file is toobig
    is_toobig: bool,
    /// Size of the file
    size: u64,
    /// True if the file type is valid
    is_type_allowed: bool,
    /// True if clamav tests pass
    av_pass: bool,
    /// Detailed report of clamav if the test failed
    av_report: Vec<String>,
    /// True if yara tests pass
    yara_pass: bool,
    /// Detailed report of yara if the test failed
    yara_report: String,
    /// Timestamp of the file entering the station
    timestamp: String,
    /// True if a file corruption occured during the processing
    is_corrupted: bool,
    /// Type of the file
    file_type: String,
}

/// Structure representing a file and its metadata in the daemon
#[derive(Debug)]
struct FileData {
    /// File descriptor
    fd: i32,
    /// Associated file metadata
    md: FileMetadata,
}

/// Metadata object in the report.
/// The structure can be serialized to JSON.
#[derive(Serialize, Deserialize, Clone)]
struct MetaData {
    /// Name of the file
    name: String,
    /// Date of the report creation
    date: String,
    /// Type of the file
    file_type: String,
    /// True if the file is correct
    is_valid: bool,
    /// Object containing the detailled [FileReport]
    report: FileReport,
}

/// Signature binding the file and the report.
/// the structure can be serialized to JSON.
#[derive(Serialize, Deserialize, Clone)]
struct Bd {
    /// SHA256 digest of the file encoded in base64
    file_digest: String,
    /// SHA256 digest of the [MetaData] associated to the file
    metadata_digest: String,
    /// Station certificates: concatenation of its ED25519 and Dilithium5 signing certificates with a '|' delimiter
    station_certificate: String,
    /// Report signature: concatenation of the ED25519 and Dilithium5 signatures in base64
    report_signature: String,
}

/// Report that will be created for each file.
/// The structure can be serialized to JSON.
#[derive(Serialize, Deserialize, Clone)]
struct Report {
    /// [MetaData] of the file analysis
    metadata: MetaData,
    /// [Bd] binding of the file and the report with the station signature
    binding: Bd,
}

/// Detailed report of the file checks.
#[derive(Serialize, Deserialize, Clone)]
struct FileReport {
    /// Detailed report of the yara checks
    yara: String,
    /// Detailed report of the clamav checks
    av: Vec<String>,
    /// True if the file type is allowed
    type_allowed: bool,
    /// Size of the file
    size: u64,
    /// True if a file corruption occured during the file processing
    corrupted: bool,
    /// True if the file size is too big
    toobig: bool,
}

/// Directory containing the station signing keys
const KEY_FILE_DIR: &str = "/etc/keysas";
/// Password for the private signing keys PKCS#8 files
const KEY_PASSWD: &str = "Keysas007";
/// Directory containing the station configuration
const CONFIG_DIRECTORY: &str = "/etc/keysas";

/// Daemon configuration arguments
struct Configuration {
    /// Path to the socket with keysas-transit
    socket_out: String,
    /// Path to the output directory
    sas_out: String,
    /// True if the file are allowed to pass even if yara failed
    yara_clean: bool,
}

/// Setup the landlock sandboxing
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
    }
}

/// This function retrieves the file descriptors and metadata from the messages
/// messages contains the file descriptor
/// buffer contains the associated file metadata
fn parse_messages(messages: Messages, buffer: &[u8]) -> Vec<FileData> {
    messages
        .filter_map(|m| m.ok())
        .filter_map(|ad| {
            // Filter AncillaryData to keep only ScmRights
            match ad {
                AncillaryData::ScmRights(scm_rights) => Some(scm_rights),
                AncillaryData::ScmCredentials(_) => None,
            }
        })
        .flatten()
        .filter_map(|fd| {
            // Deserialize metadata into a [FileMetadata] struct
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

/// Wrapper around the report metadata creation
fn generate_report_metadata(f: &FileData) -> MetaData {
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

    MetaData {
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
    }
}

/// Bind the report to file by signing with ED25519 and Dilithium5 the concatenation
/// of the file digest and the report metadata digest.
/// The two signatures are concatenated (ED25519 first).
/// All the fields of the binding are encoded in base64
fn bind_and_sign(
    f: &FileData,
    report_meta: &MetaData,
    sign_keys: &HybridKeyPair,
    sign_cert: &str,
) -> Result<Report, anyhow::Error> {
    // Compute digest of report metadata
    let json_string = serde_json::to_string(&report_meta)?;

    let mut hasher = Sha256::new();
    hasher.update(json_string.as_bytes());
    let result = hasher.finalize();

    let meta_digest = format!("{result:x}");

    // Sign the report and the file
    let concat = format!("{}-{}", f.md.digest, meta_digest);

    let mut signature = Vec::new();

    // Sign with ED25519
    signature.append(&mut sign_keys.classic.message_sign(concat.as_bytes())?);

    // Sign with Dilithium5
    signature.append(&mut sign_keys.pq.message_sign(concat.as_bytes())?);

    // Generate the final report
    Ok(Report {
        metadata: report_meta.clone(),
        binding: Bd {
            file_digest: general_purpose::STANDARD.encode(f.md.digest.clone()),
            metadata_digest: general_purpose::STANDARD.encode(meta_digest),
            station_certificate: sign_cert.to_string(),
            report_signature: general_purpose::STANDARD.encode(signature),
        },
    })
}

/// This function output files and report received from transit
/// The function first check the digest of the file received
fn output_files(
    files: Vec<FileData>,
    conf: &Configuration,
    sign_keys: &HybridKeyPair,
    sign_cert: &str,
) -> Result<()> {
    for mut f in files {
        let file = unsafe { File::from_raw_fd(f.fd) };
        // Position the cursor at the beginning of the file
        unistd::lseek(f.fd, 0, nix::unistd::Whence::SeekSet)?;
        // Check digest
        let digest = sha256_digest(&file)?;

        // Test if digest is correct
        if digest.ne(&f.md.digest) {
            warn!("Digest invalid for file {}", f.md.filename);
            f.md.is_digest_ok = false;
        }

        // Generate a report
        let report_meta = generate_report_metadata(&f);

        // Bind the report to the file and sign it
        let new_report = bind_and_sign(&f, &report_meta, sign_keys, sign_cert)?;

        // Write the report to disk
        let mut path = PathBuf::new();
        path.push(conf.sas_out.clone());
        path.push(&f.md.filename);
        let path = append_ext("krp", path);
        let mut report = File::options()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;
        let json_report = serde_json::to_string_pretty(&new_report)?;

        writeln!(report, "{}", json_report)?;

        // Test if the check passed, if yes write the file to sas_out
        if f.md.is_digest_ok
            && !f.md.is_toobig
            && f.md.is_type_allowed
            && f.md.av_pass
            && !f.md.is_corrupted
            && f.md.yara_pass
            || (!f.md.yara_pass && !conf.yara_clean)
        {
            // Output file
            let mut reader = BufReader::new(&file);

            let mut path = PathBuf::new();
            path.push(&conf.sas_out);
            path.push(&f.md.filename);

            let output = File::options().write(true).create(true).open(path)?;
            // Position the cursor at the beginning of the file
            unistd::lseek(f.fd, 0, nix::unistd::Whence::SeekSet)?;
            let mut writer = BufWriter::new(output);
            io::copy(&mut reader, &mut writer)?;
        }
        // Release the file in this daemon
        drop(file);
    }

    Ok(())
}

/// Main loop of the daemon
/// It starts by configuring the security (landlock and seccomp), it recovers the
/// station signing keys
/// Then it enters an infinite loops that:
/// 1. Get file descriptors and metadata from transit
/// 2. Parse them
/// 3. Create reports for each file and outputs them with the file to the output directory
fn main() -> Result<()> {
    // TODO activate seccomp

    // Parse command arguments
    let config = parse_args();

    // Configure logger
    init_logger();

    //Init Landlock
    landlock_sandbox(&config.sas_out)?;

    // Load station signing keys and certificate
    let sign_keys = match HybridKeyPair::load(
        "file-sign",
        Path::new(KEY_FILE_DIR),
        Path::new(KEY_FILE_DIR),
        KEY_PASSWD,
    ) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to load station signing keys {e}");
            process::exit(1);
        }
    };

    // Convert certificates to PEM string so that it can be placed in the reports
    let mut sign_cert = String::new();
    let pem_cl = match sign_keys.classic_cert.to_pem(pkcs8::LineEnding::LF) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to convert certificate to string {e}");
            process::exit(1);
        }
    };
    sign_cert.push_str(&pem_cl);
    // Add a delimiter between the two certificates
    sign_cert.push('|');
    let pem_pq = match sign_keys.pq_cert.to_pem(pkcs8::LineEnding::LF) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to convert certificate to string {e}");
            process::exit(1);
        }
    };
    sign_cert.push_str(&pem_pq);

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
        output_files(files, &config, &sign_keys, &sign_cert)?;
    }
}

#[cfg(test)]
mod tests_out {
    use base64::{engine::general_purpose, Engine};
    use ed25519_dalek::{self, Digest, Sha512};
    use keysas_lib::{certificate_field::CertificateFields, keysas_hybrid_keypair::HybridKeyPair};
    use oqs::sig::{Algorithm, Sig};
    use pkcs8::der::{DecodePem, EncodePem};
    use x509_cert::Certificate;

    use crate::{bind_and_sign, generate_report_metadata, FileData, FileMetadata};

    #[test]
    fn test_metadata_valid_file() {
        // Generate dummy file data
        let file_data = FileData {
            fd: 2,
            md: FileMetadata {
                filename: "test.txt".to_string(),
                digest: "00112233445566778899AABBCCDDEEFF".to_string(),
                is_digest_ok: true,
                is_toobig: false,
                size: 42,
                is_type_allowed: true,
                av_pass: true,
                av_report: Vec::new(),
                yara_pass: true,
                yara_report: "".to_string(),
                timestamp: "timestamp".to_string(),
                is_corrupted: false,
                file_type: "txt".to_string(),
            },
        };

        // Generate report metadata
        let meta = generate_report_metadata(&file_data);

        // Validate fields
        assert_eq!(file_data.md.filename, meta.name);
        assert_eq!(file_data.md.file_type, meta.file_type);
        assert_eq!(meta.is_valid, true);
    }

    #[test]
    fn test_bind_and_sign() {
        // Generate temporary keys
        let infos =
            CertificateFields::from_fields(None, None, None, Some("Test_station"), Some("200"))
                .unwrap();
        let sign_keys = HybridKeyPair::generate_root(&infos).unwrap();

        let mut sign_cert = String::new();
        let pem_cl = sign_keys
            .classic_cert
            .to_pem(pkcs8::LineEnding::LF)
            .unwrap();
        sign_cert.push_str(&pem_cl);
        // Add a delimiter between the two certificates
        sign_cert.push('|');
        let pem_pq = sign_keys.pq_cert.to_pem(pkcs8::LineEnding::LF).unwrap();
        sign_cert.push_str(&pem_pq);

        // Generate dummy file data
        let file_data = FileData {
            fd: 2,
            md: FileMetadata {
                filename: "test.txt".to_string(),
                digest: "00112233445566778899AABBCCDDEEFF".to_string(),
                is_digest_ok: true,
                is_toobig: false,
                size: 42,
                is_type_allowed: true,
                av_pass: true,
                av_report: Vec::new(),
                yara_pass: true,
                yara_report: "".to_string(),
                timestamp: "timestamp".to_string(),
                is_corrupted: false,
                file_type: "txt".to_string(),
            },
        };

        let meta = generate_report_metadata(&file_data);

        let report = bind_and_sign(&file_data, &meta, &sign_keys, &sign_cert).unwrap();
        // Test the generated report
        // Reconstruct the public keys from the binding certificates
        let mut certs = report.binding.station_certificate.split('|');
        let cert_cl = Certificate::from_pem(certs.next().unwrap()).unwrap();
        let cert_pq = Certificate::from_pem(certs.remainder().unwrap()).unwrap();

        let pub_cl = ed25519_dalek::PublicKey::from_bytes(
            cert_cl
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
        )
        .unwrap();
        oqs::init();
        let pq_scheme = Sig::new(Algorithm::Dilithium5).unwrap();
        let pub_pq = pq_scheme
            .public_key_from_bytes(
                cert_pq
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .raw_bytes(),
            )
            .unwrap();

        // Verify the signature of the report
        let signature = general_purpose::STANDARD
            .decode(report.binding.report_signature)
            .unwrap();
        let concat = format!(
            "{}-{}",
            String::from_utf8(
                general_purpose::STANDARD
                    .decode(report.binding.file_digest)
                    .unwrap()
            )
            .unwrap(),
            String::from_utf8(
                general_purpose::STANDARD
                    .decode(report.binding.metadata_digest)
                    .unwrap()
            )
            .unwrap()
        );

        let mut prehashed = Sha512::new();
        prehashed.update(&concat);
        assert_eq!(
            true,
            pub_cl
                .verify_prehashed(
                    prehashed,
                    None,
                    &ed25519_dalek::Signature::from_bytes(
                        &signature[0..ed25519_dalek::SIGNATURE_LENGTH]
                    )
                    .unwrap()
                )
                .is_ok()
        );

        assert_eq!(
            true,
            pq_scheme
                .verify(
                    concat.as_bytes(),
                    pq_scheme
                        .signature_from_bytes(&signature[ed25519_dalek::SIGNATURE_LENGTH..])
                        .unwrap(),
                    pub_pq
                )
                .is_ok()
        );
    }
}
