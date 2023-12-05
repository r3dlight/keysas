use std::ffi::OsString;
use std::thread;
use std::time::Duration;
use log::*;

use windows_service::define_windows_service;
use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use registry::{Data, Hive, Security};

use keysas_lib::keysas_key::{KeysasHybridPubKeys, PublicKeys};

use crate::controller::ServiceController;

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

pub fn start_windows_service() {
    service_dispatcher::start("Keysas Service", ffi_keysas_service)?;
}

pub fn load_security_policy(_config: &Config) -> Result<SecurityPolicy, anyhow::Error> {
    let regkey = match Hive::LocalMachine.open(
        r"SYSTEM\CurrentControlSet\Services\Keysas Service\config",
        Security::Read,
    ) {
        Ok(r) => r,
        Err(e) => {
            return Err(anyhow!(
                "Failed to open driver interface: Failed to open registry key {e}"
            ));
        }
    };

    let policy = SecurityPolicy {
        disable_unsigned_usb: matches!(regkey.value("DisableUnsignedUsb"), Ok(Data::U32(1))),
        allow_user_usb_authorization: matches!(
            regkey.value("AllowUserUsbAuthorization"),
            Ok(Data::U32(1))
        ),
        allow_user_file_read: matches!(regkey.value("AllowUserFileRead"), Ok(Data::U32(1))),
        allow_user_file_write: matches!(regkey.value("AllowUserFileWrite"), Ok(Data::U32(1))),
    };

    Ok(policy)
}

pub fn load_certificates(_config: &Config)
        -> Result<(KeysasHybridPubKeys, KeysasHybridPubKeys), anyhow::Error> {
    let regkey = match Hive::LocalMachine.open(
        r"SYSTEM\CurrentControlSet\Services\Keysas Service\config",
        Security::Read,
    ) {
        Ok(r) => r,
        Err(e) => {
            return Err(anyhow!(
                "Failed to open driver interface: Failed to open registry key {e}"
            ));
        }
    };

    let st_cl_path = match regkey.value("StCaClCert") {
        Ok(Data::String(s)) => s.to_string_lossy(),
        _ => {
            return Err(anyhow!("Failed to get value to path to ST CL certificate"));
        }
    };

    let st_pq_path = match regkey.value("StCaPqCert") {
        Ok(Data::String(s)) => s.to_string_lossy(),
        _ => {
            return Err(anyhow!("Failed to get value to path to ST PQ certificate"));
        }
    };

    let usb_cl_path = match regkey.value("UsbCaClCert") {
        Ok(Data::String(s)) => s.to_string_lossy(),
        _ => {
            return Err(anyhow!("Failed to get value to path to ST CL certificate"));
        }
    };

    let usb_pq_path = match regkey.value("UsbCaPqCert") {
        Ok(Data::String(s)) => s.to_string_lossy(),
        _ => {
            return Err(anyhow!("Failed to get value to path to ST PQ certificate"));
        }
    };

    let cl_cert_pem = fs::read_to_string(st_cl_path)?;
    let pq_cert_pem = fs::read_to_string(st_pq_path)?;

    let usb_cl_pem = fs::read_to_string(usb_cl_path)?;
    let usb_pq_pem = fs::read_to_string(usb_pq_path)?;

    let st_ca_pub = match KeysasHybridPubKeys::get_pubkeys_from_certs(&cl_cert_pem, &pq_cert_pem) {
        Ok(Some(pk)) => pk,
        Ok(None) => {
            return Err(anyhow!("No public key found in station CA certificates"));
        },
        Err(e) => {
            return Err(anyhow!("Failed to extract station CA certificates: {e}"));
        }
    };

    let usb_ca_pub = match KeysasHybridPubKeys::get_pubkeys_from_certs(&usb_cl_pem, &usb_pq_pem) {
        Ok(Some(pk)) => pk,
        Ok(None) => {
            return Err(anyhow!("No public key found in USB CA certificates"));
        },
        Err(e) => {
            return Err(anyhow!("Failed to extract USB CA certificates: {e}"));
        }
    };

    Ok((st_ca_pub, usb_ca_pub))
}