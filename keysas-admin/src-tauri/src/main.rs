// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-admin".
 *
 * (C) Copyright 2019-2023 Stephane Neveu
 *
 * This file contains the main function.
 */

#![forbid(unsafe_code)]
#![warn(unused_extern_crates)]
#![forbid(non_shorthand_field_patterns)]
#![warn(dead_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_copy_implementations)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unstable_features)]
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

use crate::errors::*;
use std::path::Path;
use async_std::task;
use keysas_lib::certificate_field::CertificateFields;
use keysas_lib::keysas_hybrid_keypair::HybridKeyPair;
use nom::bytes::complete::take_until;
use nom::IResult;
use sha2::{Digest, Sha256};
use std::io::Read;
use tauri::command;
use tauri::{CustomMenuItem, Menu, MenuItem, Submenu};
use tauri_plugin_store::PluginBuilder;
use std::io::BufReader;

mod errors;
mod ssh_wrapper;
use crate::ssh_wrapper::*;
mod store;
use crate::store::*;

use keysas_lib::pki::*;

// TODO: place constant paths in constants

fn main() -> Result<()> {
    // Initiliaze the logger
    simple_logger::init()?;

    // Initialize liboqs
    oqs::init();

    // Initialize Tauri

    task::block_on(init_tauri())?;
    Ok(())
}

/// Creates a sha256 hash from a file
fn sha256_digest(password: &str) -> Result<String> {
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

async fn init_tauri() -> Result<()> {
    let quit = CustomMenuItem::new("quit".to_string(), "Quit");
    //let close = CustomMenuItem::new("close".to_string(), "Close");
    let submenu = Submenu::new("Program", Menu::new().add_item(quit));
    let menu = Menu::new()
        .add_native_item(MenuItem::Copy)
        //.add_item(CustomMenuItem::new("hide", "Hide"))
        .add_submenu(submenu);
    tauri::Builder::default()
        .plugin(PluginBuilder::default().build())
        .setup(|_app| {
            if let Err(e) = init_store(STORE_PATH) {
                return Err(e.into());
            }
            Ok(())
        })
        .menu(menu)
        .on_menu_event(|event| match event.menu_item_id() {
            "quit" => {
                std::process::exit(0);
            }
            _ => {}
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
        Ok((public, private)) => {
            return Ok((public, private));
        },
        Err(e) => {
            log::error!("Failed to get ssh keys: {e}");
            return Err(String::from("Store error"));
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
        Ok(res) => {
            return Ok(res);
        },
        Err(e) => {
            log::error!("Failed to get station IP: {e}");
            return Err(String::from("Store error"));
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
            return Ok(result);
        },
        Err(e) => {
            log::error!("Failed to get station IP: {e}");
            return Err(String::from("Store error"));
        }
    }
}

/// This function initialize the keys in the station by
///  1. Generate a key pair for file signature on the station
///  2. Set correct file attributes for the private key file
///  3. Recover the public part of the key
///  4. Generate a certificate for the public key
///  5. Export the created certificate on the station
///  6. Finally it loads the admin USB signing certificate on the station
#[command]
async fn init_keysas(ip: String, name: String,
                        ca_pwd: String, st_ca_file: String, usb_ca_file: String,
                    ) -> bool {
    /*
    let private_key = match get_ssh() {
        Ok((_, private)) => private,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return false;
        } 
    };
    // Connect to the host
    let mut session = match connect_key(&ip, &private_key) {
        Ok(tu) => tu,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    //  1. Generate a key pair for file signature on the station
    //  2. Set correct file attributes for the private key file
    //  3. Recover the certification for the key
    let command = format!("{}{}{}{}{}",
                                "sudo /usr/bin/keysas-sign --generate",
                                " --name ", name,
                                " && sudo /usr/bin/chmod 600 /etc/keysas/file-sign-priv.pem",
                                " && sudo /usr/bin/chattr +i /etc/keysas/file-sign-priv.pem");
    let cert_req = match session_exec(&mut session, &command) {
        Ok(res) => {
            match X509Req::from_pem(&res) {
                Ok(req) => req,
                Err(e) => {
                    log::error!("failed to convert command output: {:?}", e);
                    session.close();
                    return false;
                }
            }
        },
        Err(why) => {
            log::error!("Error on send_command: {:?}", why);
            session.close();
            return false;
        }
    };
    // 4. Generate a certificate from the request
    // Load PKI admin key
    let (root_key, _root_cert) = match load_pkcs12(&st_ca_file, &ca_pwd) {
        Ok(k) => k,
        Err(e) => {
            log::error!("Failed to load PKI private key: {e}");
            session.close();
            return false;
        }
    };

    // Generate certificate
    let cert = match generate_cert_from_request(&cert_req, &root_key) {
        Ok(c) => c,
        Err(e) => {
            log::error!("Failed to generate certificate from request: {e}");
            session.close();
            return false;
        }
    };

    // 5. Export the created certificate on the station
    let output = match cert.to_pem() {
        Ok(o) => {
            match String::from_utf8(o) {
                Ok(out) => out,
                Err(e) => {
                    log::error!("Failed to convert certificate to string: {e}");
                    session.close();
                    return false;
                }
            }
        },
        Err(e) => {
            log::error!("Failed to convert certificate to PEM: {e}");
            session.close();
            return false;
        }
    };
    
    let command = format!("{}{}",
            "sudo /usr/bin/keysas-sign --load --certtype file --cert ",
            output);
    if let Err(e) = session_exec(&mut session, &command) {
        log::error!("Failed to load certificate on the station: {e}");
        session.close();
        return false;
    }

    // 6. Finally it loads the admin USB signing certificate
    // Load USB CA cert
    let (_usb_key, usb_cert) = match load_pkcs12(&usb_ca_file, &ca_pwd) {
        Ok(k) => k,
        Err(e) => {
            log::error!("Failed to load USB CA certificate: {e}");
            session.close();
            return false;
        }
    };

    let output = match usb_cert.to_pem() {
        Ok(o) => {
            match String::from_utf8(o) {
                Ok(out) => out,
                Err(e) => {
                    log::error!("Failed to convert USB certificate to string: {e}");
                    session.close();
                    return false;
                }
            }
        },
        Err(e) => {
            log::error!("Failed to convert USB certificate to PEM: {e}");
            session.close();
            return false;
        }
    };
    
    let command = format!("{}{}",
            "sudo /usr/bin/keysas-sign --load --certtype usb --cert ",
            output);
    if let Err(e) = session_exec(&mut session, &command) {
        log::error!("Failed to load USB certificate on the station: {e}");
        session.close();
        return false;
    }

    session.close();
    */
    true
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
        },
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
        },
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
    
    match session_upload(&mut session, &public_key.trim().to_string(),
                            &String::from("/home/keysas/.ssh/authorized_keys")) {
        Ok(_) => {
            log::info!("authorized_keys successfully s-copied !");
        },
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
            return true;
        },
        Err(e) => {
            log::error!("Rust error on open_exec: {:?}", e);
            session.close();
            return false;
        }
    }
}

/// This command test if a given station is connected or not
/// The function returns a boolean indicating the station status or an error
#[command]
fn is_alive(name: String) -> Result<bool, String> {
    if name.chars().count() == 0 {
        log::warn!("Name must not be empty");
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
        },
        Err(why) => {
            log::error!("Cannot execute command status: {:?}", why);
            session.close();
            return Err(String::from("Store error"));
        }
    }
    session.close();
    Ok(true)
}

#[command]
async fn sign_key(ip: String, password: String) -> bool {
    let private_key = match get_ssh() {
        Ok((_, private)) => private,
        Err(e) => {
            log::error!("Failed to get private key: {e}");
            return false;
        } 
    };

    let password = sha256_digest(&password.trim()).unwrap();
    
    // Connect to the host
    let host = format!("{}{}", ip.trim(), ":22");
    let mut session = match connect_key(&ip, &private_key) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    let command = format!("{}", "sudo /usr/bin/keysas-sign --watch");
    let output = match session_exec(&mut session, &command) {
        Ok(out) => out,
        Err(e) => {
            session.close();
            log::error!("Failed to connect to station: {e}");
            return false;
        }
    };

    // Replace password
    let command = match String::from_utf8(output) {
        Ok(signme) => {
            let signme = signme.trim();
            let (command, _) = parser(&signme).unwrap();
            let command = command.replace("YourSecretPassWord", password.trim());
            let command = format!("{}{}{}", "sudo /usr/bin/", command, " --force");
            log::debug!("{}", command);
            command
        },
        Err(why) => {
            log::error!("Rust error on session.open_exec: {:?}", why);
            session.close();
            return false;
        }
    };

    log::debug!("Going to sign a new USB device on keysas: {}", host);
    match session_exec(&mut session, &command) {
        Ok(_) => {
            log::info!("USB storage successfully signed !");
        },
        Err(why) => {
            log::error!("Error while sign a USB storage: {:?}", why);
            session.close();
            return false;
        }
    }
    true
}

fn parser(s: &str) -> IResult<&str, &str> {
    take_until("keysas-sign")(s)
}

fn parser_revoke(s: &str) -> IResult<&str, &str> {
    take_until("--sign")(s)
}

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
    
    let command = format!("{}", "sudo /usr/bin/keysas-sign --watch");
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
            let (command, _) = parser(&signme).unwrap();
            let (_, command) = parser_revoke(&command).unwrap();
            let command = format!(
                                    "{}{}{}",
                                    "sudo /usr/bin/",
                                    command.trim(),
                                    " --revoke"
                                );
            log::debug!("{}", command);
            command
        },
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
        },
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
fn validate_privatekey(public_key: String, private_key: String) -> bool {
    if Path::new(&public_key.trim()).is_file()
        && Path::new(&private_key.trim()).is_file()
    {
        true
    } else {
        false
    }
}

#[command]
fn validate_rootkey(root_key: String) -> bool {
    if Path::new(&root_key.trim()).is_file()
    {
        true
    } else {
        false
    }
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
fn generate_pki_in_dir(org_name: String, org_unit: String, country: String,
                                validity: String, admin_pwd: String,
                                pki_dir: String) -> Result<String, String> {
    // Validate user inputs
    let infos = match CertificateFields::from_fields (
        Some(&org_name),
        Some(&org_unit), 
        Some(&country),
        None,
        Some(&validity)) {
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
        "root",
        &Path::new(&(pki_dir.to_owned() + "/CA/root")),
        &Path::new(&(pki_dir.to_owned() + "/CA/root")),
        &admin_pwd) {
        log::error!("Failed to save root key to disk: {e}");
        return Err(String::from("PKI error"));
    }
    
    // Generate keysas station intermediate CA key pair
    let ca_infos = match CertificateFields::from_fields(
        None,
        None,
        None,
        Some("Station CA"),
        None
    ) {
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
    let st_ca_keys = match HybridKeyPair::generate_signed_keypair(&root_keys, &ca_name, &infos, false) {
        Ok(kp) => kp,
        Err(e) => {
            log::error!("Failed to generate intermediate CA for station: {e}");
            return Err(String::from("PKI error"));
        }
    };
    // Save keys
    if let Err(e) = st_ca_keys.save(
        "st-ca",
        &Path::new(&(pki_dir.to_owned() + "/CA/st")),
        &Path::new(&(pki_dir.to_owned() + "/CA/st")),
        &admin_pwd) {
        log::error!("Failed to save station CA key to disk: {e}");
        return Err(String::from("PKI error"));
    }

    // Generate USB signing key pair
    let usb_infos = match CertificateFields::from_fields(
        None,
        None,
        None,
        Some("USB admin"),
        None
    ) {
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
    let usb_keys = match HybridKeyPair::generate_signed_keypair(
        &root_keys, &usb_name, &infos, true) {
        Ok(kp) => kp,
        Err(e) => {
            log::error!("Failed to generate USB signing key pair: {e}");
            return Err(String::from("PKI error"));
        }
    };
    // Save keys
    if let Err(e) = usb_keys.save(
        "usb",
        &Path::new(&(pki_dir.to_owned() + "/CA/usb")),
        &Path::new(&(pki_dir.to_owned() + "/CA/usb")),
        &admin_pwd) {
        log::error!("Failed to save station CA key to disk: {e}");
        return Err(String::from("PKI error"));
    }

    Ok(String::from("PKI created"))
}
