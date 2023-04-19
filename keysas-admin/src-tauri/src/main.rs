// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-admin".
 *
 * (C) Copyright 2019-2023 Stephane Neveu
 *
 * This file contains the main function.
 */

//#![forbid(unsafe_code)]
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
#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]
#![feature(str_split_remainder)]

use anyhow::anyhow;
use async_std::task;
use keysas_lib::certificate_field::CertificateFields;
use keysas_lib::keysas_hybrid_keypair::HybridKeyPair;
use keysas_lib::pki::generate_cert_from_csr;
use nom::bytes::complete::take_until;
use nom::IResult;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::BufReader;
use std::io::Read;
use std::path::Path;
use tauri::command;
use tauri::{CustomMenuItem, Menu, MenuItem, Submenu};

mod ssh_wrapper;
use crate::ssh_wrapper::*;
mod store;
use crate::store::*;
mod utils;
use crate::utils::*;
mod usb_sign;
use crate::usb_sign::*;

// TODO: place constant paths in constants
const ST_CA_KEY_NAME: &str = "st-ca";
const USB_CA_KEY_NAME: &str = "usb";
const PKI_ROOT_KEY_NAME: &str = "root";

const _CA_DIR: &str = "/CA";
const ST_CA_SUB_DIR: &str = "/CA/st";
const USB_CA_SUB_DIR: &str = "/CA/usb";
const PKI_ROOT_SUB_DIR: &str = "/CA/root";
const _CRL_DIR: &str = "/CRL";
const CERT_DIR: &str = "/CERT";

fn create_dir_if_not_exist(path: &String) -> Result<(), anyhow::Error> {
    if !Path::new(path).is_dir() {
        fs::create_dir(path)?;
    }
    Ok(())
}

/// Create the PKI directory hierachy as follows
/// pki_dir
/// |-- CA
/// |   |--root
/// |   |--st
/// |   |--usb
/// |--CRL
/// |--CERT
fn create_pki_dir(pki_dir: &String) -> Result<(), anyhow::Error> {
    // Test if the directory path is valid
    if !Path::new(&pki_dir.trim()).is_dir() {
        return Err(anyhow!("Invalid PKI directory path"));
    }

    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CA"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CA/root"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CA/st"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CA/usb"))?;

    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CRL"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CERT"))?;

    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    // Initiliaze the logger
    simple_logger::init()?;

    // Initialize liboqs
    oqs::init();

    // Initialize Tauri

    task::block_on(init_tauri())?;
    Ok(())
}

/// Creates a sha256 hash from a file
fn sha256_digest(password: &str) -> Result<String, anyhow::Error> {
    let mut reader = BufReader::new(password.as_bytes());

    let digest = {
        let mut hasher = Sha256::new();
        let mut buffer = [0; 1024];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        hasher.finalize()
    };
    Ok(format!("{:x}", digest))
}

static STORE_PATH: &str = ".keysas.dat";

async fn init_tauri() -> Result<(), anyhow::Error> {
    let quit = CustomMenuItem::new("quit".to_string(), "Quit");
    //let close = CustomMenuItem::new("close".to_string(), "Close");
    let submenu = Submenu::new("Program", Menu::new().add_item(quit));
    let menu = Menu::new()
        .add_native_item(MenuItem::Copy)
        //.add_item(CustomMenuItem::new("hide", "Hide"))
        .add_submenu(submenu);
    tauri::Builder::default()
        .setup(|_app| {
            if let Err(e) = init_store(STORE_PATH) {
                return Err(e.into());
            }
            Ok(())
        })
        .menu(menu)
        .on_menu_event(|event| {
            if event.menu_item_id().eq("quit") {
                std::process::exit(0);
            }
        })
        .invoke_handler(tauri::generate_handler![
            reboot,
            update,
            init_keysas,
            shutdown,
            export_sshpubkey,
            is_alive,
            sign_key,
            revoke_key,
            validate_privatekey,
            validate_rootkey,
            generate_pki_in_dir,
            save_sshkeys,
            get_sshkeys,
            save_station,
            get_station_ip,
            list_stations,
        ])
        .run(tauri::generate_context!())?;
    Ok(())
}

/// This command saves the path to the public and private SSH keys
/// If a path already exists it is replaced
/// The returned value is a boolean indicating if an error occured during
/// the execution (true: result is ok, false: error)
#[command]
async fn save_sshkeys(public: String, private: String) -> bool {
    match set_ssh(&public, &private) {
        Ok(_) => true,
        Err(e) => {
            log::error!("Failed to save ssh keys: {e}");
            false
        }
    }
}

/// This functions get the path to the public and private SSH keys
/// The first returned value is a boolean indicating if an error occured during
/// the execution (true: result is ok, false: error)
#[command]
fn get_sshkeys() -> Result<(String, String), String> {
    match get_ssh() {
        Ok((public, private)) => Ok((public, private)),
        Err(e) => {
            log::error!("Failed to get ssh keys: {e}");
            Err(String::from("Store error"))
        }
    }
}

/// This function saves a station configuration in the database
/// If a station already exists with the same name, it is replaced
/// The returned value contains a boolean indicating if an error occured during
/// the execution (true: result is ok, false: error)
#[command]
async fn save_station(name: String, ip: String) -> bool {
    match set_station(&name, &ip) {
        Ok(_) => true,
        Err(e) => {
            log::error!("Failed to save station: {e}");
            false
        }
    }
}

/// This function returns the IP address of a station registered in the database
/// The returned value contains a boolean indicating if an error occured during
/// the execution (true: result is ok, false: error)
#[command]
fn get_station_ip(name: String) -> Result<String, String> {
    match get_station_ip_by_name(&name) {
        Ok(res) => Ok(res),
        Err(e) => {
            log::error!("Failed to get station IP: {e}");
            Err(String::from("Store error"))
        }
    }
}

/// This functions returns a list of all the station name and IP address stored
/// The list is a JSON of the form "[{name, ip}]"
#[command]
fn list_stations() -> Result<String, String> {
    match get_station_list() {
        Ok(res) => {
            let result = match serde_json::to_string(&res) {
                Ok(r) => r,
                Err(e) => {
                    log::error!("Failed to serialize result: {e}");
                    return Err(String::from("Invalid result"));
                }
            };
            log::debug!("Station list: {}", result);
            Ok(result)
        }
        Err(e) => {
            log::error!("Failed to get station IP: {e}");
            Err(String::from("Store error"))
        }
    }
}

/// This function initialize the keys in the station by
///  1. Generate a key pair for file signature on the station
///  2. Recover the public part of the key
///  3. Generate a certificate for the public key
///  4. Export the created certificate on the station
///  5. Finally it loads the admin USB signing certificate on the station
#[command]
fn init_keysas(ip: String, name: String, ca_pwd: String) -> Result<String, String> {
    /* Get admin configuration from the store */
    // Get SSH key
    let ssh_key = match get_ssh() {
        Ok((_, private)) => private,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return Err(String::from("No SSH key"));
        }
    };

    // Get path to PKI directory
    let pki_dir = match get_pki_dir() {
        Ok(dir) => dir,
        Err(e) => {
            log::error!("Failed to get PKI directory: {e}");
            return Err(String::from("Invalid PKI configuration"));
        }
    };

    // Get PKI info
    let pki_info = match get_pki_info() {
        Ok(info) => info,
        Err(e) => {
            log::error!("Failed to get PKI informations: {e}");
            return Err(String::from("Invalid PKI configuration"));
        }
    };

    // Connect to the host
    let mut session = match connect_key(&ip, &ssh_key) {
        Ok(tu) => tu,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return Err(String::from("Connection failed"));
        }
    };

    //  1. Generate a key pair for file signature on the station
    //  2. Recover the CSR for the keys
    let (csr_cl, csr_pq) = match cmd_generate_key_and_get_csr(&mut session, &name) {
        Ok(csrs) => csrs,
        Err(e) => {
            log::error!("Failed to generate key on station and get CSR: {e}");
            session.close();
            return Err(String::from("PKI error"));
        }
    };

    // 3. Generate a certificate from the request
    // Load station CA keypair
    let st_ca_keys = match HybridKeyPair::load(
        ST_CA_KEY_NAME,
        Path::new(ST_CA_SUB_DIR),
        Path::new(ST_CA_SUB_DIR),
        &ca_pwd,
    ) {
        Ok(k) => k,
        Err(e) => {
            log::error!("Failed to load station CA key: {e}");
            session.close();
            return Err(String::from("PKI error"));
        }
    };

    // Load USB CA keypair
    let usb_keys = match HybridKeyPair::load(
        USB_CA_KEY_NAME,
        Path::new(USB_CA_SUB_DIR),
        Path::new(USB_CA_SUB_DIR),
        &ca_pwd,
    ) {
        Ok(k) => k,
        Err(e) => {
            log::error!("Failed to load station USB key: {e}");
            session.close();
            return Err(String::from("PKI error"));
        }
    };

    // Generate certificate
    let cert_cl = match generate_cert_from_csr(&st_ca_keys, &csr_cl, &pki_info, true) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to generate certificate from request: {e}");
            session.close();
            return Err(String::from("PKI error"));
        }
    };

    let cert_pq = match generate_cert_from_csr(&st_ca_keys, &csr_pq, &pki_info, true) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to generate certificate from request: {e}");
            session.close();
            return Err(String::from("PKI error"));
        }
    };

    // Save certificates
    let path_cl = pki_dir.clone() + CERT_DIR + &name + "-cl.pem";
    if let Err(e) = save_certificate(&cert_cl, Path::new(&path_cl)) {
        log::error!("Failed to save station certificate: {e}");
        session.close();
        return Err(String::from("PKI error"));
    }

    let path_pq = pki_dir + CERT_DIR + &name + "-pq.pem";
    if let Err(e) = save_certificate(&cert_cl, Path::new(&path_pq)) {
        log::error!("Failed to save station certificate: {e}");
        session.close();
        return Err(String::from("PKI error"));
    }

    // 4. Export the created certificates on the station
    if let Err(e) = send_cert_to_station(&mut session, &cert_cl, "file-cl") {
        log::error!("Failed to load certificate on the station: {e}");
        session.close();
        return Err(String::from("Connection error"));
    }

    if let Err(e) = send_cert_to_station(&mut session, &cert_pq, "file-pq") {
        log::error!("Failed to load certificate on the station: {e}");
        session.close();
        return Err(String::from("Connection error"));
    }

    // 5. Finally it loads the admin USB signing certificate
    if let Err(e) = send_cert_to_station(&mut session, &usb_keys.classic_cert, "usb-cl") {
        log::error!("Failed to load certificate on the station: {e}");
        session.close();
        return Err(String::from("Connection error"));
    }

    if let Err(e) = send_cert_to_station(&mut session, &usb_keys.pq_cert, "usb-pq") {
        log::error!("Failed to load certificate on the station: {e}");
        session.close();
        return Err(String::from("Connection error"));
    }

    session.close();

    Ok(String::from("OK"))
}

#[command]
async fn update(ip: String) -> bool {
    let private_key = match get_ssh() {
        Ok((_, private)) => private,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return false;
        }
    };

    let host = format!("{}{}", ip.trim(), ":22");
    log::error!("Rust will try updating host: {}", host);

    // Connect to the host
    let mut session = match connect_key(&ip, &private_key) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    match session_exec(&mut session, &String::from("sudo /usr/bin/apt update && sudo /usr/bin/apt -y dist-upgrade && sudo /bin/systemctl reboot ")) {
        Ok(_) => {
            log::info!("Trying to update and rebooting...");
        },
        Err(why) => {
            log::error!("Error while updating: {:?}", why);
            return false;
        }
    }
    session.close();
    true
}

#[command]
async fn reboot(ip: String) -> bool {
    let private_key = match get_ssh() {
        Ok((_, private)) => private,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return false;
        }
    };
    // Connect to the host
    let host = format!("{}{}", ip.trim(), ":22");
    log::info!("Rust will try rebooting host: {}", host);
    let mut session = match connect_key(&ip, &private_key) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    match session_exec(&mut session, &String::from("sudo /bin/systemctl reboot")) {
        Ok(_) => {
            log::info!("Keysas station is rebooting !");
        }
        Err(why) => {
            log::error!("Rust error on open_exec: {:?}", why);
            return false;
        }
    }
    session.close();
    true
}

#[command]
async fn shutdown(ip: String) -> bool {
    let private_key = match get_ssh() {
        Ok((_, private)) => private,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return false;
        }
    };
    // Connect to the host
    let mut session = match connect_key(&ip, &private_key) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };
    match session_exec(&mut session, &String::from("sudo /bin/systemctl poweroff")) {
        Ok(_) => {
            log::info!("Keysas station is shutting down.");
            session.close();
        }
        Err(why) => {
            log::error!("Rust error on open_exec: {:?}", why);
            session.close();
            return false;
        }
    }

    true
}

#[command]
async fn export_sshpubkey(ip: String) -> bool {
    let public_key = match get_ssh() {
        Ok((public, _)) => public,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return false;
        }
    };
    log::info!("Exporting public SSH key to {:?}", ip);
    // Connect to the host
    let mut session = match connect_pwd(&ip) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    match session_upload(
        &mut session,
        public_key.trim(),
        &String::from("/home/keysas/.ssh/authorized_keys"),
    ) {
        Ok(_) => {
            log::info!("authorized_keys successfully s-copied !");
        }
        Err(e) => {
            log::error!("Rust error on upload: {:?}", e);
            session.close();
            return false;
        }
    }

    // Once the SSH has been copied, disable password authentication
    match session_exec(&mut session, &String::from("sudo /usr/bin/sed -i \'s/.*PasswordAuthentication.*/PasswordAuthentication no/\' /etc/ssh/sshd_config && sudo /bin/systemctl restart sshd")) {
        Ok(res) => {
            log::debug!("Command output: {}", String::from_utf8(res).unwrap());
            log::info!("Password authentication has been disabled.");
            session.close();
            true
        },
        Err(e) => {
            log::error!("Rust error on open_exec: {:?}", e);
            session.close();
            false
        }
    }
}

/// This command test if a given station is connected or not
/// The function returns a boolean indicating the station status or an error
#[command]
fn is_alive(name: String) -> Result<bool, String> {
    if name.chars().count() == 0 {
        log::warn!(" is_alive: Name must not be empty");
        return Ok(false);
    }

    let private_key = match get_ssh() {
        Ok((_, private)) => private,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return Err(String::from("Store error"));
        }
    };

    let ip = match get_station_ip_by_name(&name) {
        Ok(ip) => ip,
        Err(e) => {
            log::error!("Failed to get station ip: {e}");
            return Err(String::from("Store error"));
        }
    };

    // Connect to the host
    let mut session = match connect_key(&ip, &private_key) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return Err(String::from("Store error"));
        }
    };
    match session_exec(&mut session, &String::from("/bin/systemctl status keysas")) {
        Ok(_) => {
            log::info!("Keysas is alive.");
        }
        Err(why) => {
            log::error!("Cannot execute command status: {:?}", why);
            session.close();
            return Err(String::from("Store error"));
        }
    }
    session.close();
    Ok(true)
}

// TODO: to be modified to work locally
#[command]
async fn sign_key(password: String) -> bool {
    let device = match watch_new_usb(){
        Ok(dev) => {
            log::debug!("{dev}");
            dev
        },
        Err(e) => {
            log::error!("Error while looking for new USB device: {e}");
            return false;
        }
    };
    true
}

fn parser(s: &str) -> IResult<&str, &str> {
    take_until("keysas-sign")(s)
}

fn parser_revoke(s: &str) -> IResult<&str, &str> {
    take_until("--sign")(s)
}

// TODO: to be modified to work locally
#[command]
async fn revoke_key(ip: String) -> bool {
    let private_key = match get_ssh() {
        Ok((_, private)) => private,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return false;
        }
    };

    // Connect to the host
    let host = format!("{}{}", ip.trim(), ":22");
    let mut session = match connect_key(&ip, &private_key) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    let command = "sudo /usr/bin/keysas-sign --watch".to_string();
    let stdout = match session_exec(&mut session, &command) {
        Ok(stdout) => stdout,
        Err(e) => {
            log::error!("Error while revoking a USB storage: {:?}", e);
            session.close();
            return false;
        }
    };

    let command = match String::from_utf8(stdout) {
        Ok(signme) => {
            let signme = signme.trim();
            let (command, _) = parser(signme).unwrap();
            let (_, command) = parser_revoke(command).unwrap();
            let command = format!("{}{}{}", "sudo /usr/bin/", command.trim(), " --revoke");
            log::debug!("{}", command);
            command
        }
        Err(e) => {
            log::error!("Error while revoking a USB storage: {:?}", e);
            session.close();
            return false;
        }
    };

    log::debug!("Going to revoke a USB device on keysas: {}", host);
    match session_exec(&mut session, &command) {
        Ok(_) => {
            log::info!("USB storage successfully revoked !");
        }
        Err(e) => {
            log::error!("Error while revoking a USB storage: {:?}", e);
            session.close();
            return false;
        }
    }

    session.close();
    true
}

#[command]
async fn validate_privatekey(public_key: String, private_key: String) -> bool {
    Path::new(&public_key.trim()).is_file() && Path::new(&private_key.trim()).is_file()
}

#[command]
async fn validate_rootkey(root_key: String) -> bool {
    Path::new(&root_key.trim()).is_file()
}

/// Generate a new PKI in an empty directory
///
/// # Arguments
/// * `org_name` - String containing the organisation name of the PKI
/// * `org_unit` - String containing the organisational unit of the PKI
/// * `country` - String containing the country name of the PKI
/// * `validity` - String representation of the number of days of validity for PKI root keys
/// * `admin_pwd` - String containing the PKI administrator password
/// * `pki_dir` - String containing the path the PKI directory
///
/// # Return
/// Return a result containing an error message if any
#[command]
async fn generate_pki_in_dir(
    org_name: String,
    org_unit: String,
    country: String,
    validity: String,
    admin_pwd: String,
    pki_dir: String,
) -> Result<String, String> {
    // Validate user inputs
    let infos = match CertificateFields::from_fields(
        Some(&org_name),
        Some(&org_unit),
        Some(&country),
        None,
        Some(&validity),
    ) {
        Ok(i) => i,
        Err(_) => {
            log::error!("Failed to validate user input");
            return Err(String::from("Invalid user input"));
        }
    };
    // Validate pki_dir path and create directory hierachy
    if let Err(e) = create_pki_dir(&pki_dir) {
        log::error!("Failed to create PKI directory: {e}");
        return Err(String::from("Invalid PKI directory path"));
    }
    // Save PKI configuration
    if let Err(e) = set_pki_config(&pki_dir, &infos) {
        log::error!("Failed to save PKI configuration: {e}");
        return Err(String::from("Store error"));
    }

    // Generate root key and save them in PKCS12 format
    let root_keys = match HybridKeyPair::generate_root(&infos) {
        Ok(kp) => kp,
        Err(e) => {
            log::error!("Failed to generate PKI root keys: {e}");
            return Err(String::from("PKI error"));
        }
    };

    // Save keys
    if let Err(e) = root_keys.save(
        PKI_ROOT_KEY_NAME,
        Path::new(&(pki_dir.to_owned() + PKI_ROOT_SUB_DIR)),
        Path::new(&(pki_dir.to_owned() + PKI_ROOT_SUB_DIR)),
        &admin_pwd,
    ) {
        log::error!("Failed to save root key to disk: {e}");
        return Err(String::from("PKI error"));
    }

    // Generate keysas station intermediate CA key pair
    let ca_infos = match CertificateFields::from_fields(None, None, None, Some("Station CA"), None)
    {
        Ok(i) => i,
        Err(e) => {
            log::error!("Failed to generate station CA name field: {e}");
            return Err(String::from("PKI error"));
        }
    };
    let ca_name = match ca_infos.generate_dn() {
        Ok(n) => n,
        Err(e) => {
            log::error!("Failed to generate distinguished name for station CA: {e}");
            return Err(String::from("PKI error"));
        }
    };
    let st_ca_keys =
        match HybridKeyPair::generate_signed_keypair(&root_keys, &ca_name, &infos, false) {
            Ok(kp) => kp,
            Err(e) => {
                log::error!("Failed to generate intermediate CA for station: {e}");
                return Err(String::from("PKI error"));
            }
        };
    // Save keys
    if let Err(e) = st_ca_keys.save(
        ST_CA_KEY_NAME,
        Path::new(&(pki_dir.to_owned() + ST_CA_SUB_DIR)),
        Path::new(&(pki_dir.to_owned() + ST_CA_SUB_DIR)),
        &admin_pwd,
    ) {
        log::error!("Failed to save station CA key to disk: {e}");
        return Err(String::from("PKI error"));
    }

    // Generate USB signing key pair
    let usb_infos = match CertificateFields::from_fields(None, None, None, Some("USB admin"), None)
    {
        Ok(i) => i,
        Err(e) => {
            log::error!("Failed to generate station CA name field: {e}");
            return Err(String::from("PKI error"));
        }
    };
    let usb_name = match usb_infos.generate_dn() {
        Ok(n) => n,
        Err(e) => {
            log::error!("Failed to generate distinguished name for station CA: {e}");
            return Err(String::from("PKI error"));
        }
    };
    let usb_keys = match HybridKeyPair::generate_signed_keypair(&root_keys, &usb_name, &infos, true)
    {
        Ok(kp) => kp,
        Err(e) => {
            log::error!("Failed to generate USB signing key pair: {e}");
            return Err(String::from("PKI error"));
        }
    };
    // Save keys
    if let Err(e) = usb_keys.save(
        USB_CA_KEY_NAME,
        Path::new(&(pki_dir.to_owned() + USB_CA_SUB_DIR)),
        Path::new(&(pki_dir + USB_CA_SUB_DIR)),
        &admin_pwd,
    ) {
        log::error!("Failed to save station CA key to disk: {e}");
        return Err(String::from("PKI error"));
    }

    Ok(String::from("PKI created"))
}
