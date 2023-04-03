// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-sign".
 *
 * (C) Copyright 2019-2023 Stephane Neveu
 *
 * The code for keysas-sign binary.
 */

//! Keysas-sign is a utility on the station that manage its private keys
//! It can be called on the command line and it offers the two functions
//!  - generate_signing_keypair
//!     This command is used to generate a new signing keypair on the station that
//!     will be used to signed outgoing files and reports
//!  - save_certificate
//!     This command is used to load certificate on the station, it can be either:
//!         - file: the certificate corresponds to the private signing key of the station
//!         - usb: the certificate corresponds to the USB signing authority

pub use anyhow::{anyhow, Context, Result};
use clap::{crate_version, Arg, ArgAction, Command};
use keysas_lib::certificate_field::CertificateFields;
use pkcs8::der::EncodePem;
use std::fs::File;
use std::io::prelude::*;
mod errors;
use ed25519_dalek::Keypair;
use keysas_lib::keysas_key::KeysasKey;
use keysas_lib::keysas_key::KeysasPQKey;
use std::path::Path;
use std::str;

const FILE_PRIV_PATH: &str = "/etc/keysas/file-sign-priv.pem";
const FILE_CERT_PATH: &str = "/etc/keysas/file-sign-cert.pem";
const FILE_PRIV_PQ_PATH: &str = "/etc/keysas/file-sign-pq-priv.pem";
const FILE_CERT_PQ_PATH: &str = "/etc/keysas/file-sign-pq-cert.pem";
const USB_CERT_PATH: &str = "/etc/keysas/usb-ca-cert.pem";

const KEY_PASSWD: &str = "Keysas007";

/// Store command arguments
struct Config {
    generate: bool,    // True for the generate command
    load: bool,        // True for the load command
    name: String,      // Organisation name to put in the certificate request
    cert_type: String, // Certificate type being loaded
    cert: String,      // Certificate value
}

/// Parse command arguments
/// The tool does only two function:
///   - Generate a new file signing key
///   - Load certificate for the USB CA or its own file signing certificate
fn command_args() -> Config {
    // Start clap CLI definition
    let matches = Command::new("keysas-sign")
     .version(crate_version!())
     .author("Stephane N")
     .about("Keysas tool to manage the station signature certificates")
     .arg(
         Arg::new("generate")
             .short('g')
             .long("generate")
             .value_name("true/false")
             .help("Generate a private for signing purpose (Default is false).")
             .default_value("false")
             .action(ArgAction::SetTrue)
             //.requires("orgname")
             //.requires("orgunit")
             //.requires("country")
             .conflicts_with("load")
     )
     .arg(
         Arg::new("load")
             .short('l')
             .long("load")
             .value_name("true/false")
             .help("Load a certificate on the station of type cert_type.")
             .default_value("false")
             .action(ArgAction::SetTrue)
             .requires("certtype")
             .conflicts_with("generate")
     )
     .arg(
         Arg::new("name")
             .short('n')
             .long("name")
             .value_name("name")
             .help("Name for the station certificate")
             .default_value("")
             .action(clap::ArgAction::Set)
     )
     .arg(
         Arg::new("certtype")
             .short('t')
             .long("certtype")
             .value_name("certtype")
             .help("[file|usb]: file is the station file signature certificate, usb is the CA certificate")
             .default_value("")
             .action(clap::ArgAction::Set)
     )
     .arg(
         Arg::new("cert")
             .short('c')
             .long("cert")
             .value_name("cert")
             .help("Content of the certificate in PEM format")
             .default_value("")
             .action(clap::ArgAction::Set)
     )
     .get_matches();

    Config {
        generate: matches.get_flag("generate"),
        load: matches.get_flag("load"),
        name: matches.get_one::<String>("name").unwrap().to_string(),
        cert_type: matches.get_one::<String>("certtype").unwrap().to_string(),
        cert: matches.get_one::<String>("cert").unwrap().to_string(),
    }
}

/// Generate a new key and certification request
/// The private key is saved to a new file at privkey_path
/// The certificate request is a PEM-encoded PKCS#10 structure
fn generate_signing_keypair(config: &Config) -> Result<String, anyhow::Error> {
    // Generate the private keys
    let ec_key = Keypair::generate_new()?;
    let pq_key = KeysasPQKey::generate_new()?;

    // Save the keys
    ec_key.save_keys(Path::new(FILE_PRIV_PATH), KEY_PASSWD)?;
    pq_key.save_keys(Path::new(FILE_PRIV_PQ_PATH), KEY_PASSWD)?;

    let infos = CertificateFields::from_fields(None, None, None, Some(&config.name), None)?;

    let subject = infos.generate_dn()?;

    // Build the csr now
    let ec_csr = ec_key.generate_csr(&subject)?;
    let pq_csr = pq_key.generate_csr(&subject)?;

    let mut hybrid_csr = String::new();
    // Add the ED25519 CSR
    hybrid_csr.push_str(&ec_csr.to_pem(pkcs8::LineEnding::LF)?);
    // Add the Dilithium5 CSR
    hybrid_csr.push_str(&pq_csr.to_pem(pkcs8::LineEnding::LF)?);

    Ok(hybrid_csr)
}

fn save_certificate(cert_type: &String, cert: &String) -> Result<()> {
    if cert_type.eq("usb") {
        // Test if the certificate received is valid
        // Save it to a file
        let mut out = File::create(USB_CERT_PATH)?;
        out.write_all(cert.as_bytes())?;
    } else if cert_type.eq("file") {
        // Test if the certificate received is valid
        // Save it to a file
        let mut out = File::create(FILE_CERT_PATH)?;
        out.write_all(cert.as_bytes())?;
    } else {
        return Err(anyhow!("Invalid certificate type"));
    }
    Ok(())
}

fn main() -> Result<()> {
    let config = command_args();

    if config.generate {
        // This command generate a new signing keypair for the station
        // and generate a signing request for certificate creation by the admin
        match generate_signing_keypair(&config) {
            Ok(r) => {
                // Return the CSR
                println!("{}", r);
            }
            Err(e) => {
                return Err(anyhow!("Failed to generate private key {e}"));
            }
        }
    } else if config.load {
        match save_certificate(&config.cert_type, &config.cert) {
            Ok(_) => println!("OK"),
            Err(e) => {
                return Err(anyhow!("Failed to generate private key {e}"));
            }
        }
    }
    Ok(())
}
