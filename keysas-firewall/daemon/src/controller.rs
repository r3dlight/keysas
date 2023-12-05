// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! Service controller
//!
//! It handles communications with the HMI and the kernel filters
//! It contains the security policy and grant the authorizations for the filter
//!
//! The main architecture for the Service Controller is shown below
//!
//! ```text
//!
//!                                       User
//!                                         ▲
//!                                         │
//!                  ┌──────────────────────┼─┐
//!                  │  GUI interface       │ │ Authorization request
//!                  │       ┌──────────────┼─┘
//!                  │       │              │
//!                  │       │  ┌───────────────────────┐
//! ┌─────────────┐  │       │  │                       │
//! │             │  │modif_req │  Service Controller   │
//! │  Tray App   │ ──────────► │                       │
//! │             │  │       │  │ - Security Policy     │
//! │             │ ◄────────── │                       │
//! └─────────────┘  │notif  │  │                       │
//!                  └───────┘  └───────────────────────┘
//!                                ▲  │        ▲     │
//!                  ──────────────┼──┼────────┼─────┼───────────
//!                                │  │    req │     │ modif_req
//!                  kernel        │  ▼        │     ▼
//!                          ┌─────────────┐ ┌─────────────┐
//!                          │ USB monitor │ │ File filter │
//!                          └─────────────┘ └─────────────┘
//! ```
//!
//! USB authorization
//!
//! USB device authorization is based on the security policy setting and the
//! signature of the USB device MBR.
//!
//! ```text
//!                               ///
//!                              /////
//!                               ///
//!                                │
//!                                │
//!  [USB not signed               ▼
//!   or invalid signature] ┌─────────────┐        [USB signature is valid]
//!               ┌─────────│   Pending   │───────────────────────┐
//!               │         └─────────────┘                       │
//!               │                                               │
//!  Block all    │              Allow only read access for valid │
//!  files on     │               and ask user if                 │
//!  the USB key  │               allow_user_file_read = true     │
//!       \       │                                        \      │
//!        \      ▼                                         \     ▼
//!     ┌───────────┐                                       ┌───────────┐
//!     │   Block   │                                       │ Read only │
//!     └───────────┘                                       └───────────┘
//!           │                                                 │
//!           │ [disable_unsigned_usb                           │ [allow_user
//!           │  || (allow_user_usb_authorization               │   _file_write]
//!           │        && user input ok)]                       │
//!           ▼                                                 ▼
//!     ┌───────────┐                                      ┌────────────┐
//!     │ Allow All │                                      │ Read Write │
//!     └───────────┘                                      └────────────┘
//!         /                                                 /
//!        /                                                 /
//!  Allow all file             Allow read to valid file and ask user if
//!  access on USB              allow_user_file_read = true to read invalid file
//!                             and ask user for all write access
//!
//! ```

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

use anyhow::anyhow;
use base64::{engine::general_purpose, Engine as _};
use ed25519_dalek::Signature as SignatureDalek;
use log::*;
use oqs::sig::{Algorithm, Sig};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::{OsStr, OsString},
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
};

use crate::file_filter_if::{FileFilterInterface, FileFilterInterfaceBuilder};
use crate::gui_interface::{
    FileUpdateMessage, GuiInterface, GuiInterfaceBuilder, UsbUpdateMessage,
};
use crate::usb_monitor::{UsbMonitor, UsbMonitorBuilder};
use crate::Config;
use keysas_lib::{
    // file_report::parse_report,
    keysas_key::{KeysasHybridPubKeys, KeysasHybridSignature, PublicKeys},
};

#[cfg(target_os = "windows")]
use crate::windows::service::{load_certificates, load_security_policy};

#[cfg(target_os = "linux")]
use crate::linux::service::{load_certificates, load_security_policy};

/// Authorization states for USB devices
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum UsbAuthorization {
    /// Authorization request pending
    Pending = 0,
    /// Access is blocked
    Block,
    /// Access is allowed in read mode only
    AllowRead,
    /// Access is allowed with a warning to the user
    AllowRW,
    /// Access is allowed for all operations
    AllowAll,
}

impl UsbAuthorization {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Authorization states for files
#[derive(Debug, Deserialize, Serialize, Clone, Copy, PartialEq)]
#[repr(u8)]
pub enum FileAuthorization {
    /// Authorization request pending
    Pending = 0,
    /// Access is blocked
    Block,
    /// Access is allowed in read mode only
    AllowRead,
    /// Access is allowed in read/write mode
    AllowRW,
}

impl FileAuthorization {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Main firewall security configuration
/// It set on start up by the administrator
#[derive(Debug, Deserialize, Clone, Copy, Default)]
pub struct SecurityPolicy {
    /// If true disable USB signature verification, all USB keys are allowed
    pub disable_unsigned_usb: bool,
    /// If true allow the user to manualy authorize unsigned USB keys
    pub allow_user_usb_authorization: bool,
    /// If true allow the user to grant read access to unverified file
    pub allow_user_file_read: bool,
    /// If true allow the user to grant write access to files
    pub allow_user_file_write: bool,
}

/// Service controller object, it contains handles to the service communication interfaces and data
pub struct ServiceController {
    driver_if: Box<dyn FileFilterInterface + Sync + Send>,
    usb_monitor: Box<dyn UsbMonitor + Sync + Send>,
    gui: Box<dyn GuiInterface + Sync + Send>,
    policy: SecurityPolicy,
    st_ca_pub: KeysasHybridPubKeys,
    usb_ca_pub: KeysasHybridPubKeys,
    unmounted_usb: HashMap<OsString, UsbDevicePolicy>,
    mounted_usb: HashMap<OsString, UsbDevicePolicy>,
}

/// Representation of USB device in the firewall
#[derive(Debug, Clone)]
pub struct UsbDevice {
    /// Device identifier
    pub device_id: OsString,
    /// Partition identifier
    pub mnt_point: Option<OsString>,
    pub vendor: OsString,
    pub model: OsString,
    pub revision: OsString,
    pub serial: OsString,
}

/// Firewall policy for one USB device
pub struct UsbDevicePolicy {
    /// Usb device information
    device: UsbDevice,
    /// Authorization status
    auth: UsbAuthorization,
}

/// Representation of a file in the firewall
#[derive(Debug, Clone)]
pub struct FilteredFile {
    /// Path to the file
    pub path: Option<OsString>,
    /// Identifier based on SHA-256 of path
    pub id: [u8; 32],
}

/// Firewall policy for one file
pub struct FilePolicy {
    file: FilteredFile,
    auth: FileAuthorization,
}

impl ServiceController {
    /// Initialize the service controller
    pub fn init(config: &Config) -> Result<Arc<Mutex<ServiceController>>, anyhow::Error> {
        let policy = match load_security_policy(config) {
            Ok(p) => p,
            Err(e) => {
                return Err(anyhow!(
                    "ServiceController init: Failed to load security policy {e}"
                ));
            }
        };
        log::info!("Policy loaded");

        // Load local certificates for the CA
        let (st_ca_pub, usb_ca_pub) = match load_certificates(config) {
            Ok(c) => c,
            Err(e) => {
                return Err(anyhow!(
                    "ServiceController init: Failed to load certificates {e}"
                ));
            }
        };

        // Start the interface with the kernel driver
        let driver_if = FileFilterInterfaceBuilder::build()?;

        let usb_monitor = UsbMonitorBuilder::build()?;

        let gui = GuiInterfaceBuilder::build()?;

        // Initialize the controller
        let ctrl = Arc::new(Mutex::new(ServiceController {
            driver_if,
            usb_monitor,
            gui,
            policy,
            st_ca_pub,
            usb_ca_pub,
            unmounted_usb: HashMap::new(),
            mounted_usb: HashMap::new(),
        }));

        // Start the interfaces
        {
            let mut ctrl_hdl = ctrl.lock().unwrap();
            ctrl_hdl.gui.start(&ctrl)?;
            ctrl_hdl.driver_if.start(&ctrl)?;
            ctrl_hdl.usb_monitor.start(&ctrl)?;
        }

        Ok(ctrl)
    }

    /// Called by the GUI to update a USB key policy in the firewall
    ///
    /// # Arguments
    ///
    /// * `update` - Contains the new authorization status requested by the user
    pub fn request_usb_update(&self, _update: &UsbUpdateMessage) -> Result<(), anyhow::Error> {
        todo!()
    }

    /// Called by the GUI to update a File policy in the firewall
    ///
    /// # Arguments
    ///
    /// * `update` - Contains the new authorization status requested by the user
    pub fn request_file_update(&self, _update: &FileUpdateMessage) -> Result<(), anyhow::Error> {
        todo!()
    }

    /// Check a USB device to allow it not
    /// Return Ok(true) or Ok(false) according to the authorization
    ///
    /// # Arguments
    ///
    /// * `device` - Usb device info
    pub fn authorize_usb(
        &mut self,
        device: &UsbDevice,
        signature: Option<&str>,
    ) -> Result<bool, anyhow::Error> {
        info!("Received USB device request: {:?}", device);

        // TODO - Improve list of USB device
        // TODO - If mount point is given insert it in correct list

        // Test if the USB device does not already exists
        if self.unmounted_usb.contains_key(&device.device_id) {
            return Ok(false);
        }

        // Insert the new device in the list of unmounted devices
        self.unmounted_usb.insert(
            device.device_id.clone(),
            UsbDevicePolicy {
                device: device.clone(),
                auth: UsbAuthorization::Pending,
            },
        );

        // Evaluate USB key policy
        let auth = match signature {
            Some(sig) => match self.validate_usb_signature(&device, &sig) {
                Ok(true) => match self.policy.allow_user_file_write {
                    true => UsbAuthorization::AllowRW,
                    false => UsbAuthorization::AllowRead,
                },
                Ok(false) => match self.policy.disable_unsigned_usb {
                    true => UsbAuthorization::AllowAll,
                    false => UsbAuthorization::Block,
                },
                Err(e) => {
                    let dev_policy = self.unmounted_usb.get_mut(&device.device_id).unwrap();
                    dev_policy.auth = UsbAuthorization::Block;
                    return Err(e);
                }
            },
            None => match self.policy.disable_unsigned_usb {
                true => UsbAuthorization::AllowAll,
                false => UsbAuthorization::Block,
            },
        };
        let dev_policy = self.unmounted_usb.get_mut(&device.device_id).unwrap();
        dev_policy.auth = auth;

        // TODO - Update HMI

        // Return authorization decision as boolean
        match auth {
            UsbAuthorization::Block | UsbAuthorization::Pending => Ok(false),
            _ => Ok(true),
        }
    }

    /// Update information about a USB device
    ///
    /// # Arguments
    ///
    /// * `device` - information on the usb key
    pub fn update_usb(&self, _device: &UsbDevice) -> Result<(), anyhow::Error> {
        todo!()
    }

    /// Decide to authorize a file
    /// This method is called by the file filter interface
    /// Start by whitelisting file that belongs to Windows and remove directories
    /// Then try to validate it with a station report
    /// Finaly if it fails ask the user to validate it manualy
    ///
    /// USB_op will be used to apply a device wide filter policy
    ///
    /// Returns the authorization decision
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the file
    /// * `write` - If write access is requested
    pub fn authorize_file(&self, file: &FilteredFile, _write: bool) -> Result<bool, anyhow::Error> {
        let file_path = match &file.path {
            Some(p) => {
                let mut pb = PathBuf::new();
                pb.push(&p);
                pb
            },
            None => {
                return Err(anyhow!("Invalid file"));
            }
        };

        // Try to get the parent directory
        let mut components = file_path.as_path().components();

        // First component is the Root Directory
        // If the second directory is "System Volume Information" then it is internal to windows, skip it
        loop {
            let c = components.next();
            if c.is_none() || c == Some(Component::RootDir) {
                break;
            }
        }

        if components.next() == Some(Component::Normal(OsStr::new("System Volume Information"))) {
            return Ok(true);
        }

        // Skip the directories
        if file_path.metadata()?.is_dir() {
            return Ok(true);
        }

        // Try to validate the file from the station report
        match self.validate_file(file_path.as_path()) {
            Ok(true) => {
                return Ok(true);
            }
            _ => {
                info!("File not validated by station");
            }
        }

        // If the validation fails, ask the user authorization
        self.user_authorize_file(file_path.as_path())
    }

    /// Handle requests coming from the driver
    /// Return the authorization state for the USB device or the file, or an error
    ///
    /// # Arguments
    ///
    /// * 'operation' - Operation code
    /// * 'content' - Content of the request
    // pub fn handle_driver_request(
    //     &self,
    //     operation: KeysasFilterOperation,
    //     content: &[u16],
    // ) -> Result<KeysasAuthorization, anyhow::Error> {
    //     // Dispatch the request
    //     let result = match operation {
    //         KeysasFilterOperation::ScanFile => {
    //             match self.authorize_file(operation, content) {
    //                 Ok((result, true)) => {
    //                     // Send the authorization result to the tray interface
    //                     if let Err(e) = tray_interface::send_file_auth_status(content, result) {
    //                         error!("Failed to send file status to tray app {e}");
    //                     }
    //                     result
    //                 }
    //                 Ok((result, false)) => result,
    //                 Err(e) => {
    //                     error!("Failed to validate the file: {e}");
    //                     KeysasAuthorization::AuthBlock
    //                 }
    //             }
    //         }
    //         KeysasFilterOperation::ScanUsb => KeysasAuthorization::AuthAllowAll, // For now, allow all
    //     };

    //     Ok(result)
    // }

    /// Handle a request coming from the HMI
    fn handle_tray_request(&self, req: &FileUpdateMessage) -> Result<(), anyhow::Error> {
        // Check that the request is conforme to the security policy
        if (FileAuthorization::AllowRead == req.authorization) && !self.policy.allow_user_file_read
        {
            return Err(anyhow!("Authorization change not allowed"));
        }

        if (FileAuthorization::AllowRW == req.authorization)
            && (!self.policy.allow_user_file_read || !self.policy.allow_user_file_write)
        {
            return Err(anyhow!("Authorization change not allowed"));
        }

        // Create the request for the driver
        // The format is :
        //   - FileID: 32 bytes
        //   - New authorization: 1 byte
        let mut request: [u8; 33] = [0; 33];
        let mut index = 0;

        for db in req.id {
            let bytes = db.to_ne_bytes();
            request[index] = bytes[0];
            request[index + 1] = bytes[1];
            index += 2;
        }
        request[32] = req.authorization.as_u8();

        // Send the request to the driver
        // if let Err(e) = self.driver_if.send_msg(&request) {
        //     return Err(anyhow!("Failed to pass tray request to driver {e}"));
        // }

        Ok(())
    }

    fn validate_usb_signature(
        &self,
        device: &UsbDevice,
        sig_block: &str,
    ) -> Result<bool, anyhow::Error> {
        let mut signatures = sig_block.split('|');

        // Extract ED25519 signature
        let sig_cl = match signatures.next() {
            Some(s) => s,
            None => {
                return Err(anyhow!("Cannot extract ED25519 signature"));
            }
        };

        let sig_cl_dec = match general_purpose::STANDARD.decode(sig_cl) {
            Ok(s) => s,
            Err(_e) => {
                return Err(anyhow!("Failed to parse ED25519 signature"));
            }
        };

        let mut sig_cl_dec_casted: [u8; 64] = [0u8; 64];
        if sig_cl_dec.len() == 64_usize {
            sig_cl_dec_casted.copy_from_slice(&sig_cl_dec);
        } else {
            return Err(anyhow!("Signature is not 64 bytes long"));
        }

        let sig_dalek = SignatureDalek::from_bytes(&sig_cl_dec_casted);

        let sig_pq = match signatures.remainder() {
            Some(s) => s,
            None => {
                return Err(anyhow!("Cannot extract Dilithium 5 signature"));
            }
        };

        let sig_pq_dec = match general_purpose::STANDARD.decode(sig_pq) {
            Ok(s) => s,
            Err(_e) => {
                return Err(anyhow!("Failed to parse Dilithium 5 signature"));
            }
        };

        oqs::init();
        let pq_scheme = match Sig::new(Algorithm::Dilithium5) {
            Ok(pq_s) => pq_s,
            Err(e) => return Err(anyhow!("Cannot construct new Dilithium5 algorithm: {e}")),
        };

        let sig_pq = match pq_scheme.signature_from_bytes(&sig_pq_dec) {
            Some(sig) => sig,
            None => return Err(anyhow!("Cannot parse PQ signature from bytes")),
        };

        let hybrid_sig = KeysasHybridSignature {
            classic: sig_dalek,
            pq: sig_pq.to_owned(),
        };

        let data = format!(
            "{:?}/{:?}/{:?}/{:?}/{}",
            device.vendor, device.model, device.revision, device.serial, "out"
        );

        match KeysasHybridPubKeys::verify_key_signatures(
            data.as_bytes(),
            &hybrid_sig,
            &self.usb_ca_pub,
        ) {
            Ok(_) => Ok(true),
            Err(_e) => Ok(false),
        }
    }

    /// Check a file
    ///  - If it is a normal file, try to find the corresponding station report
    ///     - If there is none, return False
    ///     - If there is one, validate both
    ///  - If the file is a station report, try to find the corresponding file
    ///     - If there is none, try to validate the report alone. There must be no file digest referenced in it
    ///     - If there is one, validate both
    ///
    /// # Arguments
    ///
    /// * 'path' - Path to the file
    fn validate_file(&self, path: &Path) -> Result<bool, anyhow::Error> {
        // Test if the file is a station report
        if Path::new(path)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("krp"))
        {
            // Try to find the corresponding file
            let mut file_path = path.to_path_buf();
            // file_path.file_name should not be None at this point
            file_path.set_extension("");

            match file_path.is_file() {
                true => {
                    // If it exists, validate both
                    // match parse_report(
                    //     Path::new(path),
                    //     Some(&file_path),
                    //     Some(&self.ca_cert_cl),
                    //     Some(&self.ca_cert_pq),
                    // ) {
                    //     Ok(_) => return Ok(true),
                    //     Err(e) => {
                    //         info!("Failed to parse report: {e}");
                    //         return Ok(false);
                    //     }
                    // }
                }
                false => {
                    // If no corresponding file validate it alone
                    // match parse_report(
                    //     Path::new(path),
                    //     None,
                    //     Some(&self.ca_cert_cl),
                    //     Some(&self.ca_cert_pq),
                    // ) {
                    //     Ok(_) => return Ok(true),
                    //     Err(e) => {
                    //         info!("Failed to parse report: {e}");
                    //         return Ok(false);
                    //     }
                    // }
                }
            }
        }

        // If not try to find the corresponding report
        // It should be in the same directory with the same name + '.krp'
        let mut path_report = PathBuf::from(path);
        match path_report.extension() {
            Some(ext) => {
                let mut ext = ext.to_os_string();
                ext.push(".krp");
                path_report.set_extension(ext);
            }
            _ => {
                path_report.set_extension(".krp");
            }
        }
        match path_report.is_file() {
            true => {
                // If a corresponding report is found then validate both the file and the report
                // if let Err(e) = parse_report(
                //     path_report.as_path(),
                //     Some(path),
                //     Some(&self.ca_cert_cl),
                //     Some(&self.ca_cert_pq),
                // ) {
                //     info!("Failed to parse file and report: {e}");
                //     return Ok(false);
                // }
                Ok(true)
            }
            false => {
                // There is no corresponding report for validating the file
                info!("No report found at {:?}", path_report);
                Ok(false)
            }
        }
    }

    /// Spawn a dialog box to ask the user to validate a file or not
    /// Return Ok(true) or Ok(false) accordingly
    ///
    /// # Arguments
    ///
    /// * 'path' - Path to the file
    fn user_authorize_file(&self, path: &Path) -> Result<bool, anyhow::Error> {
        // Find authorization status for the file
        todo!()
    }
}