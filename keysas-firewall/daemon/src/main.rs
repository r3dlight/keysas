// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! KeysasMinifilterInterface is a generic interface to send and receive messages
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
#![warn(overflowing_literals)]
#![warn(deprecated)]
#![warn(unused_imports)]
#![feature(vec_into_raw_parts)]
#![feature(str_split_remainder)]

pub mod controller;
pub mod driver_interface;
pub mod tray_interface;

use crate::controller::ServiceController;

use clap::{crate_version, Arg, ArgAction, Command};
use std::ffi::OsString;
use std::thread;
use std::time::Duration;
use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;

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
    // TODO - Add revocation mecanism configuration (OCSP IP or CRL IP)
}

impl Default for Config {
    fn default() -> Self {
        Self {
            config: "./keysas-firewall-conf.toml".to_string(),
            ca_cert_cl: "./st-ca-cl.pem".to_string(),
            ca_cert_pq: "./st-ca-pq.pem".to_string(),
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

define_windows_service!(ffi_keysas_service, keysas_service_main);

fn keysas_service_main(_args: Vec<OsString>) {
    // Declare service event handler
    let event_handler = move |event| -> ServiceControlHandlerResult {
        match event {
            ServiceControl::Stop => {
                log::info!("Service asked to stop");
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    // Register the service handler
    let status_handle = match service_control_handler::register("Keysas", event_handler) {
        Ok(h) => h,
        Err(e) => {
            log::error!("Failed to get status handle: {e}");
            return;
        }
    };

    // Start running the service
    if let Err(e) = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS, // Run the service in a separate process
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }) {
        log::error!("Failed to set service status to running: {e}");
        return;
    };

    log::info!("Keysas service started");

    // Start the service
    let config = Config::default();
    let _ = thread::spawn(move || {
        // Initialize and start the service
        if let Err(e) = ServiceController::init(&config) {
            log::error!("Failed to start the service: {e}");
            return;
        }

        // Put the service in sleep until it receives request from the driver or the HMI
        loop {
            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    })
    .join();

    // If the thread exits stop the service
    if let Err(e) = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    }) {
        log::error!("Failed to set service status to stop: {e}");
        return;
    };

    log::warn!("Keysas service stopped");
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

    // Register Keysas service with the system and start the service
    service_dispatcher::start("Keysas Service", ffi_keysas_service)?;

    Ok(())
}
