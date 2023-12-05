// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Keysas daemon is the main component of the firewall. It orchestrates the
//! firewall filters in the kernel based on the security policy and bridges the
//! kernel components with the user interface. The main function initialize the
//! daemon or service and then launch the ServiceController wich is the main
//! orchestrator.

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
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]
#![feature(vec_into_raw_parts)]
#![feature(str_split_remainder)]

#[macro_use]
extern crate rust_i18n;
// Initialize user strings
i18n!("locales");

pub mod controller;
pub mod file_filter_if;
pub mod gui_interface;
pub mod usb_monitor;

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
use crate::windows::service;

#[cfg(target_os = "linux")]
pub mod linux;

use clap::{crate_version, Arg, ArgAction, Command};

use log::*;

/// Configuration parameters for the service
#[derive(Debug)]
pub struct Config {
    /// Path to the security policy configuration file
    config: String,
    /// Path to the CA ED25519 certificate
    ca_cert_cl: String,
    /// Path to the CA Dilithium 5 certificate
    ca_cert_pq: String,
    /// Path to the USB CA ED25519 certificate
    usb_ca_cl: String,
    /// Path to the USB CA Dilithium 5 certificate
    usb_ca_pq: String, // TODO - Add revocation mecanism configuration (OCSP IP or CRL IP)
}

/// Set default path for the configuration files on linux
/// - security policy in ./keysas-firewall-conf.toml
/// - Station CA ED25519 certificate in ./st-ca-cl.pem
/// - Station CA Dilithium 5 certificate in ./st-ca-pq.pem
/// - USB CA ED25519 certificate in ./usb-ca-cl.pem
/// - USB CA Dilithium 5 certificate in ./usb-ca-pq.pem
///
/// Note: on Windows the default configuration is set via Registry keys
impl Default for Config {
    fn default() -> Self {
        Self {
            config: "./keysas-firewall-conf.toml".to_string(),
            ca_cert_cl: "./st-ca-cl.pem".to_string(),
            ca_cert_pq: "./st-ca-pq.pem".to_string(),
            usb_ca_cl: "./usb-ca-cl.pem".to_string(),
            usb_ca_pq: "./usb-ca-pq.pem".to_string(),
        }
    }
}

/// Get the command line arguments
fn command_args(config: &mut Config) {
    let matches = Command::new("keysas-usbfilter-daemon.exe")
        .version(crate_version!())
        .author("Luc B.")
        .about("Keysas firewall Windows service")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("Name of security policy configuration file")
                .default_value("./keysas-firewall-conf.toml")
                .action(ArgAction::Set)
                .help("Name of security policy configuration file"),
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
        .arg(
            Arg::new("usb_cl")
                .long("usb_cl")
                .value_name("Path to the USB CA ED25519 certificate")
                .default_value("./usb-ca-cl.pem")
                .action(ArgAction::Set)
                .help("Path to the USB CA ED25519 certificate"),
        )
        .arg(
            Arg::new("usb_pq")
                .long("usb_pq")
                .value_name("Path to the USB CA Dilithium 5 certificate")
                .default_value("./usb-ca-pq.pem")
                .action(ArgAction::Set)
                .help("Path to the USB CA Dilithium 5 certificate"),
        )
        .get_matches();

    // Won't panic according to clap authors because there are default values
    if let Some(p) = matches.get_one::<String>("config") {
        config.config = p.to_string();
    }
    if let Some(p) = matches.get_one::<String>("ca_cl") {
        config.ca_cert_cl = p.to_string();
    }
    if let Some(p) = matches.get_one::<String>("ca_pq") {
        config.ca_cert_pq = p.to_string();
    }
    if let Some(p) = matches.get_one::<String>("usb_cl") {
        config.usb_ca_cl = p.to_string();
    }
    if let Some(p) = matches.get_one::<String>("usb_pq") {
        config.usb_ca_pq = p.to_string();
    }
}

fn main() -> Result<(), anyhow::Error> {
    // Initialize the logger
    #[cfg(target_os = "linux")]
    {
        simple_logger::init()?;
    }

    #[cfg(target_os = "windows")]
    {
        eventlog::init("Keysas Service", log::Level::Trace)?;
    }

    info!("Event log initialized");

    // Get command arguments
    let mut config = Config::default();
    command_args(&mut config);

    // Start the service
    #[cfg(target_os = "linux")]
    {
        // Initialize and start the service
        if let Err(e) = ServiceController::init(&config) {
            log::error!("Failed to start the service: {e}");
            return Err(anyhow!("Failed to start the service: {e}"));
        }

        // Put this thread to sleep
        loop {
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Register Keysas service with the system and start the service
        service::start_windows_service(true)?;

        Ok(())
    }
}
