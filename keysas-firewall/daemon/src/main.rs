// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! KeysasDriverInterface is a generic interface to send and receive messages
//! to the firewall driver in kernel space.
//! The interface directs call to the Windows interface

#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]
#![warn(trivial_numeric_casts)]
#![warn(unused_extern_crates)]
#![warn(unused_import_braces)]
#![warn(unused_qualifications)]
#![warn(variant_size_differences)]
#![forbid(private_in_public)]
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]

#![feature(vec_into_raw_parts)]
#![feature(str_split_remainder)]

pub mod driver_interface;
pub mod tray_interface;
pub mod controller;
pub mod usb_monitor;

use crate::controller::ServiceController;
use crate::usb_monitor::KeysasUsbMonitor;

use clap::{crate_version, Arg, ArgAction, Command};
use anyhow::anyhow;

/// Configuration parameters for the service
#[derive(Debug)]
pub struct Config {
    /// Path to the security policy configuration file
    config: String,
    /// Path to the CA ED25519 certificate
    ca_cert_cl: String,
    /// Path to the CA Dilithium 5 certificate
    ca_cert_pq: String,
    // TODO - Add revocation mecanism configuration (OCSP IP or CRL IP)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config: "./keysas-firewall-conf.toml".to_string(),
            ca_cert_cl: "./st-ca-cl.pem".to_string(),
            ca_cert_pq: "./st-ca-pq.pem".to_string()
        }
    }
}

fn command_args(config: &mut Config) {
    let matches = Command::new("keysas-usbfilter-daemon.exe")
        .version(crate_version!())
        .author("Luc B.")
        .about("Keysas firewall Windows service")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("Path to security policy configuration")
                .default_value("./keysas-firewall-conf.toml")
                .action(ArgAction::Set)
                .help("Path to security policy configuration"),
        )
        .arg(
            Arg::new("ca_cl")
                .short('l')
                .long("ca_cl")
                .value_name("Path to CA ED25519 certificate")
                .default_value("./st-ca-cl.pem")
                .action(ArgAction::Set)
                .help("Path to CA ED25519 certificate"),
        )
        .arg(
            Arg::new("ca_pq")
                .short('q')
                .long("ca_pq")
                .value_name("Path to CA Dilithium 5 certificate")
                .default_value("./st-ca-pq.pem")
                .action(ArgAction::Set)
                .help("Path to CA Dilithium 5 certificate"),
        )
        .get_matches();

    //Won't panic according to clap authors because there are default values
    if let Some(p) = matches.get_one::<String>("config") {
        config.config = p.to_string();
    }
    if let Some(p) = matches.get_one::<String>("ca_cl") {
        config.ca_cert_cl = p.to_string();
    }
    if let Some(p) = matches.get_one::<String>("ca_pq") {
        config.ca_cert_pq = p.to_string();
    }
}

fn main() -> Result<(), anyhow::Error> {
    // Initialize the logger
    simple_logger::init()?;

    if let Err(e) = KeysasUsbMonitor::start_usb_monitor() {
        println!("Failed to start usb monitor: {e}");
    }

    /*
    // Get command arguments
    let mut config = Config::default();
    command_args(&mut config);

    // Initialize and start the service
    if let Err(e) = ServiceController::init(&config) {
        log::error!("Failed to start the service: {e}");
        return Err(anyhow!("Failed to start the service: {e}"));
    }

    */
    // Put the service in sleep until it receives request from the driver or the HMI
    loop {
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}
