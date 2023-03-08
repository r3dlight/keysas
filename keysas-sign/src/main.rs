// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-sign".
 *
 * (C) Copyright 2019-2023 Stephane Neveu
 *
 * The code for keysas-sign binary.
 */

use anyhow::anyhow;
use clap::{crate_version, Arg, ArgAction, Command};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::x509::X509;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509ReqBuilder;
use std::error::Error;
use std::fs::File;
use std::io::prelude::*;
mod errors;
use crate::errors::*;
extern crate libc;
extern crate udev;
use std::str;

const FILE_PRIV_PATH: &str = "/etc/keysas/file-sign-priv.pem";
const FILE_CERT_PATH: &str = "/etc/keysas/file-sign-cert.pem";
const USB_CERT_PATH: &str = "/etc/keysas/usb-ca-cert.pem";

/// Store command arguments
struct Config {
    generate:  bool,
    load:      bool,
    org_name:  String,
    org_unit:  String,
    country:   String,
    cert_type: String,
    cert:      String
}

/// Parse command arguments
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
            .requires("orgname")
            .requires("orgunit")
            .requires("country")
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
        Arg::new("orgname")
            .long("orgname")
            .value_name("orgname")
            .help("Organisation name for the station certificate")
            .default_value("")
    )
    .arg(
        Arg::new("orgunit")
            .long("orgunit")
            .value_name("orgunit")
            .help("Organisation unit name for the station certificate")
            .default_value("")
    )
    .arg(
        Arg::new("country")
            .long("country")
            .value_name("country")
            .help("Country name for the station certificate")
            .default_value("")
    )
    .arg(
        Arg::new("certtype")
            .long("certtype")
            .value_name("certtype")
            .help("[file|usb]: file is the station file signature certificate, usb is the CA certificate")
            .default_value("")
    )
    .arg(
        Arg::new("cert")
            .long("cert")
            .value_name("cert")
            .help("Content of the certificate in PEM format")
            .default_value("")
    )
    .get_matches();

    Config {
        generate:  matches.get_flag("generate"),
        load:      matches.get_flag("load"),
        org_name:  matches.get_one::<String>("orgname").unwrap().to_string(),
        org_unit:  matches.get_one::<String>("orgunit").unwrap().to_string(),
        country:   matches.get_one::<String>("country").unwrap().to_string(),
        cert_type: matches.get_one::<String>("certtype").unwrap().to_string(),
        cert:      matches.get_one::<String>("cert").unwrap().to_string()
    }
}

/// Generate a new key and certification request
/// The private key is saved to a new file at privkey_path
/// The certificate request is a PEM-encoded PKCS#10 structure
fn generate_signing_keypair(config: &Config) -> Result<Vec<u8>, Box<dyn Error>>{
    // Generate the private key
    let key = PKey::generate_ed25519()?;

    // Store the private key in a PEM encoded PKCS8 file
    let buf = key.private_key_to_pem_pkcs8()?;
    let mut output = File::create(FILE_PRIV_PATH)?;
    output.write_all(&buf)?;

    // Generate the certification request
    let mut builder = X509ReqBuilder::new()?;
    
    // Set version
    builder.set_version(2)?;

    // Set subject name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, &config.org_name)?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, &config.org_unit)?;
    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, &config.country)?;
    let name = name_builder.build();
    builder.set_subject_name(name.as_ref())?;

    // Set public key
    let raw_pub = key.raw_public_key()?;
    let pub_key = PKey::public_key_from_raw_bytes(&raw_pub, key.id())?;
    builder.set_pubkey(pub_key.as_ref())?;

    // Set request
    builder.sign(&key, MessageDigest::null())?;

    let req = builder.build();
    let out = req.to_pem()?;

    Ok(out)
}

fn save_certificate(cert_type: &String, cert: &String) -> Result<()> {
    if cert_type.eq("usb") {
        // Test if the certificate received is valid
        X509::from_pem(cert.as_bytes())?;
        // Save it to a file
        let mut out = File::create(USB_CERT_PATH)?;
        out.write_all(cert.as_bytes())?;
    } else if cert_type.eq("file") {
        // Test if the certificate received is valid
        X509::from_pem(cert.as_bytes())?;
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
        let req = match generate_signing_keypair(&config) {
            Ok(r) => r,
            Err(e) => {
                return Err(anyhow!("Failed to generate private key {e}"));
            }
        };

        println!("{:?}", req);
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