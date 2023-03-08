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
use async_std::path::Path;
use async_std::task;
use nom::bytes::complete::take_until;
use nom::IResult;
use openssl::pkey::Id;
use sha2::{Digest, Sha256};
use std::io::Read;
use tauri::command;
use tauri::{CustomMenuItem, Menu, MenuItem, Submenu};
use tauri_plugin_store::PluginBuilder;
use regex::Regex;
use std::io::BufReader;

mod errors;
mod pki;
use crate::pki::*;
mod ssh_wrapper;
use crate::ssh_wrapper::*;

use openssl::pkey::PKey;

// TODO: place constant paths in constants

fn main() -> Result<()> {
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
            generate_keypair,
            sign_key,
            revoke_key,
            validate_privatekey,
            generate_pki_in_dir,
        ])
        .run(tauri::generate_context!())?;
    Ok(())
}

/// This function initialize the keys in the station by
///  1. Generate a key pair for file signature on the station
///  2. Set correct file attributes for the private key file
///  3. Recover the public part of the key
///  4. Generate a certificate for the public key
///  5. Export the created certificate on the station
///  6. Finally it loads the admin USB signing certificate on the station
/// Rule for password
///  - At least 8 chars
#[command]
async fn init_keysas(ip: String, name: String, pki_pwd: String,
                        private_key: String) -> bool {
    // Connect to the host
    let host = format!("{}{}", ip.trim(), ":22");
    let mut session = match connect_key(&ip, &private_key) {
        Ok(tu) => tu,
        Err(e) => {
            println!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    let password = "Changeme007";

    let command = format!("{}{}{}","sudo /usr/bin/keysas-sign --generate --password=", password, " && sudo /usr/bin/chmod 600 /etc/keysas/keysas.priv && sudo /usr/bin/chattr +i /etc/keysas/keysas.priv");
    let pubkey = match session_exec(&mut session, &command) {
        Ok(res) => {
            println!("New signing keypair successfully generated.");
            match String::from_utf8(res) {
                Ok(key) => key,
                Err(e) => {
                    println!("failed to convert command output: {:?}", e);
                    return false;
                }
            }
        },
        Err(why) => {
            println!("Error on send_command: {:?}", why);
            return false;
        }
    };
    // 4. Generate a certificate from the public key
    //  5. Export the created certificate on the station
    //  6. Finally it loads the admin USB signing certificate

    session.close();

    true
}

#[command]
async fn update(ip: String, private_key: String) -> bool {
    let host = format!("{}{}", ip.trim(), ":22");
    println!("Rust will try updating host: {}", host);

    // Connect to the host
    let host = format!("{}{}", ip.trim(), ":22");
    let mut session = match connect_key(&ip, &private_key) {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    match session_exec(&mut session, &String::from("sudo /usr/bin/apt update && sudo /usr/bin/apt -y dist-upgrade && sudo /bin/systemctl reboot ")) {
        Ok(_) => {
                                        println!("Trying to update and rebooting...");
                                    },
                                    Err(why) => {
                                        println!("Error while updating: {:?}", why);
                                        return false;
                                    }
                                }
    session.close();                    
    true
}

#[command]
async fn reboot(ip: String, private_key: String) -> bool {
    // Connect to the host
    let host = format!("{}{}", ip.trim(), ":22");
    println!("Rust will try rebooting host: {}", host);
    let mut session = match connect_key(&ip, &private_key) {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    match session_exec(&mut session, &String::from("sudo /bin/systemctl reboot")) {
        Ok(_) => {
            println!("Keysas station is rebooting !");
        },
        Err(why) => {
            println!("Rust error on open_exec: {:?}", why);
            return false;
        }
    }
    session.close();
    true
}

#[command]
async fn shutdown(ip: String, private_key: String) -> bool {
    // Connect to the host
    let host = format!("{}{}", ip.trim(), ":22");
    let mut session = match connect_key(&ip, &private_key) {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };
    match session_exec(&mut session, &String::from("sudo /bin/systemctl poweroff")) {
        Ok(_) => {
            println!("Keysas station is shutting down.");
            session.close();
        },
        Err(why) => {
            println!("Rust error on open_exec: {:?}", why);
            session.close();
            return false;
        }
    }

    true
}

#[command]
async fn export_sshpubkey(ip: String, public_key: String) -> bool {
    println!("Exporting public SSH key to {:?}", ip);
    // Connect to the host
    let host = format!("{}{}", ip.trim(), ":22");
    let mut session = match connect_pwd(&ip) {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };
    
    match session_upload(&mut session, &public_key.trim().to_string(),
                            &String::from("/home/keysas/.ssh/authorized_keys")) {
        Ok(_) => {
            println!("authorized_keys successfully s-copied !");
        },
        Err(e) => {
            println!("Rust error on upload: {:?}", e);
            session.close();
            return false;            
        }
    }
    
    // Once the SSH has been copied, disable password authentication
    match session_exec(&mut session, &String::from("sudo /usr/bin/sed -i \'s/.*PasswordAuthentication.*/PasswordAuthentication no/\' /etc/ssh/sshd_config && sudo /bin/systemctl restart sshd")) {
        Ok(res) => {
            println!("Command output: {}", String::from_utf8(res).unwrap());
            println!("Password authentication has been disabled.");
            session.close();
            return true;
        },
        Err(e) => {
            println!("Rust error on open_exec: {:?}", e);
            session.close();
            return false;
        }
    }
}

#[command]
async fn is_alive(ip: String, private_key: String) -> bool {
    // Connect to the host
    let host = format!("{}{}", ip.trim(), ":22");
    let mut session = match connect_key(&ip, &private_key) {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };
    match session_exec(&mut session, &String::from("/bin/systemctl status keysas")) {
        Ok(_) => {
            println!("Keysas is alive.");
        },
        Err(why) => {
            println!("Cannot execute command status: {:?}", why);
            session.close();
            return false;
        }
    }
    session.close();
    true
}

/// This function initialize the keys in the station by
///  0. Test if new password is robust
///  1. Generate a key pair for file signature on the station
///  2. Set correct file attributes for the private key file
///  3. Recover the public part of the key
///  4. Generate a certificate for the public key
///  5. Export the created certificate on the station
///  6. Finally it loads the admin USB signing certificate
/// Rule for password
///  - At least 12 chars
#[command]
async fn generate_keypair(ip: String, private_key: String, password: String) -> bool {
    // 0. Test if new password is robust
    let reg = match Regex::new(r"^.{12,}$") {
        Ok(r) => r,
        Err(e) => {
            println!("Failed to generate regex: {e}");
            return false;
        }
    };
    if !reg.is_match(&password) {
        println!("Password must be at least 12 chars");
        return false;
    }
    let password = sha256_digest(&password.trim()).unwrap();

    // Connect to the host
    let host = format!("{}{}", ip.trim(), ":22");
    let mut session = match connect_key(&ip, &private_key) {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    // 1. Generate a keypair for file signature
    // 2. set correct attributes for private key file
    // 3. Get the public part of the key
    let command = format!("{}{}{}","sudo /usr/bin/keysas-sign --generate --password=", password, " && sudo /usr/bin/chmod 600 /etc/keysas/keysas.priv && sudo /usr/bin/chattr +i /etc/keysas/keysas.priv");
    let pubkey = match session_exec(&mut session, &command) {
        Ok(res) => {
            println!("New signing keypair successfully generated.");
            match String::from_utf8(res) {
                Ok(key) => key,
                Err(e) => {
                    println!("failed to convert command output: {:?}", e);
                    return false;
                }
            }
        },
        Err(why) => {
            println!("Error on open_exec: {:?}", why);
            return false;
        }
    };
    // 4. Generate a certificate from the public key
    //  5. Export the created certificate on the station
    //  6. Finally it loads the admin USB signing certificate
            
    true
}

#[command]
async fn sign_key(ip: String, private_key: String, password: String) -> bool {
    let password = sha256_digest(&password.trim()).unwrap();
    
    // Connect to the host
    let host = format!("{}{}", ip.trim(), ":22");
    let mut session = match connect_key(&ip, &private_key) {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };

    let command = format!("{}", "sudo /usr/bin/keysas-sign --watch");
    let output = match session_exec(&mut session, &command) {
        Ok(out) => out,
        Err(e) => {
            session.close();
            println!("Failed to connect to station: {e}");
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
            println!("{}", command);
            command
        },
        Err(why) => {
            println!("Rust error on session.open_exec: {:?}", why);
            session.close();
            return false;
        }
    };

    println!("Going to sign a new USB device on keysas: {}", host);
    match session_exec(&mut session, &command) {
        Ok(_) => {
            println!("USB storage successfully signed !");
        },
        Err(why) => {
            println!("Error while sign a USB storage: {:?}", why);
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
async fn revoke_key(ip: String, private_key: String) -> bool {
    
    // Connect to the host
    let host = format!("{}{}", ip.trim(), ":22");
    let mut session = match connect_key(&ip, &private_key) {
        Ok(s) => s,
        Err(e) => {
            println!("Failed to open ssh connection with station: {e}");
            return false;
        }
    };
    
    let command = format!("{}", "sudo /usr/bin/keysas-sign --watch");
    let stdout = match session_exec(&mut session, &command) {
        Ok(stdout) => stdout,
        Err(e) => {
            println!("Error while revoking a USB storage: {:?}", e);
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
            println!("{}", command);
            command
        },
        Err(e) => {
            println!("Error while revoking a USB storage: {:?}", e);
            session.close();
            return false;
        }
    };

    println!("Going to revoke a USB device on keysas: {}", host);
    match session_exec(&mut session, &command) {
        Ok(_) => {
            println!("USB storage successfully revoked !");
        },
        Err(e) => {
            println!("Error while revoking a USB storage: {:?}", e);
            session.close();
            return false;
        }
    }

    session.close();
    true
}

#[command]
async fn validate_privatekey(public_key: String, private_key: String) -> bool {
    if Path::new(&public_key.trim()).is_file().await
        && Path::new(&private_key.trim()).is_file().await
    {
        true
    } else {
        false
    }
}

#[command]
async fn validate_rootkey(root_key: String) -> bool {
    if Path::new(&root_key.trim()).is_file().await
    {
        true
    } else {
        false
    }
}

/// Generate a new PKI in an empty directory
#[command]
async fn generate_pki_in_dir(org_name: String, org_unit: String, country: String,
                                validity: String, sig_algo: String, admin_pwd: String,
                                pki_dir: String) -> bool {
    // Validate user inputs
    let infos = match validate_input_cert_fields(&org_name, &org_unit, 
                                            &country, &validity, &sig_algo) {
        Ok(i) => i,
        Err(_) => {
            println!("Failed to validate user input");
            return false;
        }
    };
    // Test if the directory is valid
    if Path::new(&pki_dir.trim()).is_dir().await
    {
        // Create the root CA key pair
        let root_key = match infos.sig_algo {
            Id::ED448 => {
                match PKey::generate_ed448() {
                    Ok(k) => k,
                    Err(e) => {
                        println!("Failed to generate root CA private key: {e}");
                        return false;
                    }
                }
            },
            _ => {
                match PKey::generate_ed25519() {
                    Ok(k) => k,
                    Err(e) => {
                        println!("Failed to generate root CA private key: {e}");
                        return false;
                    }
                }
            }
        };

        // Generate root certificate
        let root_cert = match generate_root_cert(root_key.as_ref(), &infos) {
            Ok(c) => c,
            Err(e) => {
                println!("Failed to generate root certificate: {e}");
                return false;
            }
        };

        // Create Keysas station CA key pair
        let (st_key, st_cert) = match generate_signed_keypair(root_key.as_ref(), &infos) {
            Ok(p) => p,
            Err(e) => {
                println!("Failed to generate Station signing key pair: {e}");
                return false;
            }
        };

        // Create the USB signing key pair
        let (usb_key, usb_cert) = match generate_signed_keypair(root_key.as_ref(), &infos) {
            Ok(p) => p,
            Err(e) => {
                println!("Failed to generate USB key pair: {e}");
                return false;
            }
        };

        // Store the PKI in PKCS#12 files
        let base_path = match pki_dir.ends_with("/") {
            true => pki_dir,
            false => {
                format!("{}{}", &pki_dir, "/")
            }
        };
        let root_path = format!("{}{}", &base_path, "root.pk12");
        if let Err(e) = store_pkcs12(&admin_pwd, 
                                                        &String::from("Root CA"),
                                                        root_key.as_ref(),
                                                        root_cert.as_ref(),
                                                        &root_path) {
            println!("Failed to store root key: {e}");
            return false;
        }

        let usb_path = format!("{}{}", &base_path, "usb.pk12");
        if let Err(e) = store_pkcs12(&admin_pwd, 
                                                        &String::from("USB"),
                                                        usb_key.as_ref(),
                                                        usb_cert.as_ref(),
                                                        &usb_path) {
            println!("Failed to store root key: {e}");
            return false;
        }

        let st_path = format!("{}{}", &base_path, "st.pk12");
        if let Err(e) = store_pkcs12(&admin_pwd, 
                                                        &String::from("Station CA"),
                                                        st_key.as_ref(),
                                                        st_cert.as_ref(),
                                                        &st_path) {
            println!("Failed to store root key: {e}");
            return false;
        }

        true
    } else {
        false
    }
}