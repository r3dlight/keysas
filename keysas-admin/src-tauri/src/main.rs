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
use sha2::{Digest, Sha256};
use ssh_rs::algorithm;
use ssh_rs::ssh;
use ssh_rs::SessionConnector;
use ssh_rs::SshResult;
use std::io::Read;
use std::net::TcpStream;
use tauri::command;
use tauri::{CustomMenuItem, Menu, MenuItem, Submenu};
use tauri_plugin_store::PluginBuilder;
use regex::Regex;
use std::io::BufReader;

mod errors;
mod pki;
use crate::pki::*;

use openssl::pkey::PKey;

const TIMEOUT: u64 = 60 * 1000;
const USER: &str = "keysas";
const PASSWORD: &str = "Changeme007";

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

/// Create SSH connexion with password
fn connect_pwd(ip: &String) -> SshResult<SessionConnector<TcpStream>> {
    let host = format!("{}{}", ip.trim(), ":22");
    ssh::create_session_without_default()
        .username(USER)
        .password(PASSWORD)
        .add_kex_algorithms(algorithm::Kex::Curve25519Sha256)
        .add_kex_algorithms(algorithm::Kex::EcdhSha2Nistrp256)
        .add_pubkey_algorithms(algorithm::PubKey::SshEd25519)
        .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_512)
        .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
        .add_enc_algorithms(algorithm::Enc::Chacha20Poly1305Openssh)
        .add_compress_algorithms(algorithm::Compress::None)
        .add_mac_algortihms(algorithm::Mac::HmacSha2_512)
        .add_mac_algortihms(algorithm::Mac::HmacSha2_256)
        .timeout(TIMEOUT.into())
        .connect(host)
}

/// Create SSH connexion with RSA or ECC key
fn connect_key(ip: &String, private_key: &String) -> SshResult<SessionConnector<TcpStream>> {
    let host = format!("{}{}", ip.trim(), ":22");
    ssh::create_session_without_default()
        .username(USER)
        .private_key_path(private_key.trim())
        .add_kex_algorithms(algorithm::Kex::Curve25519Sha256)
        .add_kex_algorithms(algorithm::Kex::EcdhSha2Nistrp256)
        .add_pubkey_algorithms(algorithm::PubKey::SshEd25519)
        .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_512)
        .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
        .add_enc_algorithms(algorithm::Enc::Chacha20Poly1305Openssh)
        .add_compress_algorithms(algorithm::Compress::None)
        .add_mac_algortihms(algorithm::Mac::HmacSha2_512)
        .add_mac_algortihms(algorithm::Mac::HmacSha2_256)
        .timeout(TIMEOUT.into())
        .connect(host)
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

#[command]
async fn update(ip: String, private_key: String) -> bool {
    let host = format!("{}{}", ip.trim(), ":22");
    println!("Rust will try updating host: {}", host);
    match connect_key(&ip, &private_key) {
        Ok(session) => {
            let mut session = session.run_local();
            match session.open_exec() {
                            Ok(exec) => {
                                match exec.send_command("sudo /usr/bin/apt update && sudo /usr/bin/apt -y dist-upgrade && sudo /bin/systemctl reboot ") {
                                    Ok(_) => {
                                        println!("Trying to update and rebooting...");
                                        session.close();
                                    },
                                    Err(why) => {
                                        println!("Error while updating: {:?}", why);
                                        return false;
                                    }
                                }
                            }
                            Err(why) => {
                                println!("Cannot create session.exec.open_exec(): {:?}.", why);
                                return false;
                            }
                        }
        }
        Err(why) => {
            println! {"Cannot create SSH session with USER and private_key: {:?}.", why};
            return false;
        }
    }

    true
}

#[command]
async fn reboot(ip: String, private_key: String) -> bool {
    let host = format!("{}{}", ip.trim(), ":22");
    println!("Rust will try rebooting host: {}", host);
    match connect_key(&ip, &private_key) {
        Ok(session) => {
            let mut session = session.run_local();
            match session.open_exec() {
                Ok(exec) => match exec.send_command("sudo /bin/systemctl reboot") {
                    Ok(_) => {
                        println!("Keysas station is rebooting !");
                        session.close();
                    }
                    Err(why) => {
                        println!("Rust error on open_exec: {:?}", why);
                        return false;
                    }
                },
                Err(why) => {
                    println!("Cannot create session.exec.open_exec(): {:?}.", why);
                    return false;
                }
            }
        }
        Err(why) => {
            println! {"Cannot create SSH session with USER and private_key: {:?}.", why};
            return false;
        }
    }

    true
}

#[command]
async fn shutdown(ip: String, private_key: String) -> bool {
    let host = format!("{}{}", ip.trim(), ":22");
    println!("Rust will try halting host: {}", host);
    match connect_key(&ip, &private_key) {
        Ok(session) => {
            let mut session = session.run_local();
            match session.open_exec() {
                Ok(exec) => match exec.send_command("sudo /bin/systemctl poweroff") {
                    Ok(_) => {
                        println!("Keysas station is shutting down.");
                        session.close();
                    }
                    Err(why) => {
                        println!("Rust error on open_exec: {:?}", why);
                        return false;
                    }
                },
                Err(why) => {
                    println!("Cannot create session.exec.open_exec(): {:?}.", why);
                    return false;
                }
            }
        }
        Err(why) => {
            println! {"Cannot create SSH session with USER and private_key: {:?}.", why};
            return false;
        }
    }

    true
}

#[command]
async fn export_sshpubkey(ip: String, public_key: String) -> bool {
    println!("Exporting public SSH key to {:?}", ip);
    match connect_pwd(&ip) {
        Ok(session) => {
            println!("Adding SSH pubkey to host: {:?}", ip);
            let mut session = session.run_local();
            match session.open_scp() {
                Ok(scp) => {
                    match scp.upload(public_key.trim(), "/home/keysas/.ssh/authorized_keys") {
                        Ok(_) => {
                            println!("authorized_keys successfully s-copied !");
                            // Once the SSH has been copied, disable password authentication
                            match session.open_exec() {
                                Ok(exec) => match exec.send_command("sudo /usr/bin/sed -i \'s/.*PasswordAuthentication.*/PasswordAuthentication no/\' /etc/ssh/sshd_config && sudo /bin/systemctl restart sshd") {
                                    Ok(res) => {
                                        println!("Command output: {}", String::from_utf8(res).unwrap());
                                        println!("Password authentication has been disabled.");
                                        session.close();
                                        return true;
                                    },
                                    Err(why) => {
                                        println!("Rust error on open_exec: {:?}", why);
                                        session.close();
                                        return false;
                                    }
                                },
                                Err(why) => {
                                    println!("Cannot create session.exec.open_exec(): {:?}.", why);
                                    session.close();
                                    return false;
                                }
                            }
                        }
                        Err(why) => {
                            println!(
                                "Error while scp authorized_keys to remote Keysas station: {:?}",
                                why
                            );
                            session.close();
                            return false;
                        }
                    }
                }
                Err(why) => {
                    println!("Cannot create new channel.open_scp(): {:?}", why);
                    session.close();
                    return false;
                }
            }
        }
        Err(_) => {
            println! {"Keysas station not reachable."};
            return false;
        }
    }
}

#[command]
async fn is_alive(ip: String, private_key: String) -> bool {
    match connect_key(&ip, &private_key) {
        Ok(session) => {
            let mut session = session.run_local();
            match session.open_exec() {
                Ok(exec) => match exec.send_command("/bin/systemctl status keysas") {
                    Ok(_) => (println!("Keysas is alive."), session.close()),
                    Err(why) => {
                        println!("Cannot execute command status: {:?}", why);
                        return false;
                    }
                },
                Err(why) => {
                    println!("Error on open_exec: {:?}", why);
                    return false;
                }
            };
        }
        Err(_) => {
            println! {"Keysas {} is unreachable.", ip};
            return false;
        }
    };

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
            println!("Failed to generate regex");
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
    match connect_key(&ip, &private_key) {
        Ok(session) => {
            let mut session = session.run_local();
            match session.open_exec() {
                Ok(exec) => {
                    // 1. Generate a keypair for file signature
                    // 2. set correct attributes for private key file
                    // 3. Get the public part of the key
                    let command = format!("{}{}{}","sudo /usr/bin/keysas-sign --generate --password=", password, " && sudo /usr/bin/chmod 600 /etc/keysas/keysas.priv && sudo /usr/bin/chattr +i /etc/keysas/keysas.priv");
                    let pubkey = match exec.send_command(&command) {
                        Ok(res) => {
                            println!("New signing keypair successfully generated.");
                            match String::from_utf8(res) {
                                Ok(key) => key,
                                Err(e) => {
                                    println!("failed to convert command output: {:?}", e);
                                    return false;
                                }
                            }
                        }
                        Err(why) => {
                            println!("Error on open_exec: {:?}", why);
                            return false;
                        }
                    };
                    // 4. Generate a certificate from the public key
                    //  5. Export the created certificate on the station
                    //  6. Finally it loads the admin USB signing certificate
                }
                Err(why) => {
                    println!("Error while trying session.open_exec: {:?}", why);
                    return false;
                }
            }
        }
        Err(why) => {
            println! {"Cannot create SSH session with USER and private_key: {:?}.", why};
            return false;
        }
    }

    true
}

#[command]
async fn sign_key(ip: String, private_key: String, password: String) -> bool {
    let password = sha256_digest(&password.trim()).unwrap();
    //println!("sign: Password digest is: {}", password);
    let host = format!("{}{}", ip.trim(), ":22");

    match connect_key(&ip, &private_key) {
        Ok(session) => {
            println!("Watching for new USB storage on host: {}", &host);
            let mut session = session.run_local();
            match session.open_exec() {
                Ok(exec) => {
                    let command = format!("{}", "sudo /usr/bin/keysas-sign --watch");
                    match exec.send_command(&command) {
                        Ok(stdout) => {
                            // Replace password
                            match String::from_utf8(stdout) {
                                Ok(signme) => {
                                    let signme = signme.trim();
                                    let (command, _) = parser(&signme).unwrap();
                                    let command =
                                        command.replace("YourSecretPassWord", password.trim());
                                    let command =
                                        format!("{}{}{}", "sudo /usr/bin/", command, " --force");
                                    println!("{}", command);
                                    println!("Going to sign a new USB device on keysas: {}", host);
                                    match session.open_exec() {
                                        Ok(exec) => match exec.send_command(&command) {
                                            Ok(_) => {
                                                println!("USB storage successfully signed !");
                                            }
                                            Err(why) => {
                                                println!(
                                                    "Error while sign a USB storage: {:?}",
                                                    why
                                                );
                                                return false;
                                            }
                                        },
                                        Err(why) => {
                                            println!(
                                                "Error while trying session.open_exec: {:?}",
                                                why
                                            );
                                            return false;
                                        }
                                    }
                                }
                                Err(why) => {
                                    println!("Error parsing stdout to String: {:?}", why);
                                    return false;
                                }
                            }
                        }
                        Err(why) => {
                            println!("Rust error on session.open_exec: {:?}", why);
                            return false;
                        }
                    }
                }
                Err(why) => {
                    println!("Rust error on session.open_exec: {:?}", why);
                    return false;
                }
            }
            session.close();
        }
        Err(why) => {
            println! {"Cannot create SSH session with USER and private_key: {:?}.", why};
            return false;
        }
    }
    println!("Password is: {}", password);
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
    let host = format!("{}{}", ip.trim(), ":22");

    match connect_key(&ip, &private_key) {
        Ok(session) => {
            println!("Watching for new USB storage on host: {}", &host);
            let mut session = session.run_local();
            match session.open_exec() {
                Ok(exec) => {
                    let command = format!("{}", "sudo /usr/bin/keysas-sign --watch");
                    match exec.send_command(&command) {
                        Ok(stdout) => match String::from_utf8(stdout) {
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
                                println!("Going to revoke a USB device on keysas: {}", host);
                                match session.open_exec() {
                                    Ok(exec) => match exec.send_command(&command) {
                                        Ok(_) => {
                                            println!("USB storage successfully revoked !");
                                        }
                                        Err(why) => {
                                            println!(
                                                "Error while revoking a USB storage: {:?}",
                                                why
                                            );
                                            return false;
                                        }
                                    },
                                    Err(why) => {
                                        println!("Error while trying session.open_exec: {:?}", why);
                                        return false;
                                    }
                                }
                            }
                            Err(why) => {
                                println!("Error parsing stdout to String: {:?}", why);
                                return false;
                            }
                        },
                        Err(why) => {
                            println!("Error on session.send_command: {:?}", why);
                            return false;
                        }
                    }
                }
                Err(why) => {
                    println!("Error on session.open_exec: {:?}", why);
                    return false;
                }
            }
            session.close();
        }
        Err(why) => {
            println! {"Cannot create SSH session with USER and private_key: {:?}.", why};
            return false;
        }
    }

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
async fn generate_pki_in_dir(pki_dir: String, admin_pwd: String) -> bool {
    // Test if the directory is valid
    if Path::new(&pki_dir.trim()).is_dir().await
    {
        // Create the root CA key pair
        let root_key = match PKey::generate_ed25519() {
            Ok(k) => k,
            Err(e) => {
                println!("Failed to generate root CA private key: {e}");
                return false;
            }
        };

        // Generate root certificate
        let fields = CertificateFields{validity: 3650};
        let root_cert = match generate_root_cert(root_key.as_ref(), &fields) {
            Ok(c) => c,
            Err(e) => {
                println!("Failed to generate root certificate: {e}");
                return false;
            }
        };

        // Store root key and certificate in PKCS#12

        //let rd = match BigNum::new_secure()

        // Create Keysas station CA key pair
        let (st_key, st_cert) = match generate_signed_keypair(root_key.as_ref()) {
            Ok(p) => p,
            Err(e) => {
                println!("Failed to generate Station signing key pair: {e}");
                return false;
            }
        };

        // Create the USB signing key pair
        let (usb_key, usb_cert) = match generate_signed_keypair(root_key.as_ref()) {
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