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

use std::io::BufReader;
mod errors;

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

#[command]
async fn generate_keypair(ip: String, private_key: String, password: String) -> bool {
    let password = sha256_digest(&password.trim()).unwrap();
    //println!("generate: Password digest is: {}", password);
    let host = format!("{}{}", ip.trim(), ":22");
    println!(
        "Rust will try generating a signing keypair on host: {}",
        host
    );
    match connect_key(&ip, &private_key) {
        Ok(session) => {
            let mut session = session.run_local();
            match session.open_exec() {
                Ok(exec) => {
                    let command = format!("{}{}{}","sudo /usr/bin/keysas-sign --generate --password=", password, " && sudo /usr/bin/chmod 600 /etc/keysas/keysas.priv && sudo /usr/bin/chattr +i /etc/keysas/keysas.priv");
                    match exec.send_command(&command) {
                        Ok(_) => {
                            println!("New signing keypair successfully generated.");
                            session.close();
                        }
                        Err(why) => {
                            println!("Error on open_exec: {:?}", why);
                            return false;
                        }
                    }
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
