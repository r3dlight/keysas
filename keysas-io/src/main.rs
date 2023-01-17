// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-io".
 *
 * (C) Copyright 2019-2023 Stephane Neveu
 *
 * This file is the main file for udev management.
 */

#![feature(atomic_from_mut)]

extern crate libc;
extern crate regex;
extern crate udev;

use anyhow::anyhow;
use clap::{crate_version, Arg, Command as Clap_Command};
use regex::Regex;
use std::fs::{self, create_dir_all};
use std::path::PathBuf;
use std::thread as sthread;
use std::{ffi::OsStr, net::TcpListener, thread::spawn};
use tungstenite::{
    accept_hdr,
    handshake::server::{Request, Response},
    Message,
};
use udev::Event;
use walkdir::WalkDir;

extern crate minisign;
extern crate proc_mounts;
extern crate serde;
extern crate serde_json;
extern crate sys_mount;

#[macro_use]
extern crate serde_derive;

use crate::errors::*;
use crossbeam_utils::thread;
use kv::Config as kvConfig;
use kv::*;
use libc::{c_int, c_short, c_ulong, c_void};
use minisign::PublicKeyBox;
use minisign::SignatureBox;
use nom::bytes::complete::take;
use nom::error::Error;
use nom::number::complete::be_u32;
use proc_mounts::MountIter;
use std::fmt::Write;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::ops::Deref;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::ptr;
use std::str;
use std::sync::Arc;
use std::time::Duration;
use sys_mount::unmount;
use sys_mount::{FilesystemType, Mount, MountFlags, SupportedFilesystems, Unmount, UnmountFlags};
use yubico_manager::config::Config;
use yubico_manager::config::{Mode, Slot};
use yubico_manager::Yubico;

mod errors;
//use std::process::exit;

#[repr(C)]
struct pollfd {
    fd: c_int,
    events: c_short,
    revents: c_short,
}

#[repr(C)]
struct sigset_t {
    __private: c_void,
}

#[allow(non_camel_case_types)]
type nfds_t = c_ulong;

const POLLIN: c_short = 0x0001;

extern "C" {
    fn ppoll(
        fds: *mut pollfd,
        nfds: nfds_t,
        timeout_ts: *mut libc::timespec,
        sigmask: *const sigset_t,
    ) -> c_int;
}

#[derive(Serialize, Deserialize, Debug)]
struct Yubistruct {
    active: bool,
    yubikeys: Vec<String>,
}
#[derive(Serialize, Deserialize, Debug)]
pub struct Usbkeys {
    usb_in: Vec<String>,
    usb_out: Vec<String>,
    usb_undef: Vec<String>,
    yubikeys: Yubistruct,
}

trait StrExt {
    fn remove_last(&self) -> &str;
}

impl StrExt for str {
    fn remove_last(&self) -> &str {
        match self.char_indices().next_back() {
            Some((i, _)) => &self[..i],
            None => self,
        }
    }
}

fn list_yubikey() -> Vec<String> {
    let mut yubi = Yubico::new();
    let mut yubikey_vector = Vec::new();

    if let Ok(device) = yubi.find_yubikey() {
        //println!(
        //    "Vendor ID: {:?} Product ID {:?}",
        //    device.vendor_id, device.product_id
        //);
        let concat = format!("{:?}/{:?}", device.vendor_id, device.product_id);
        yubikey_vector.push(concat);
    } else {
        println!("Fido2: Yubikey not present !");
    }

    yubikey_vector
}

fn hmac_challenge() -> Option<String> {
    // TODO: Must be improved to manage all cases
    if Path::new("/etc/keysas/yubikey_db").is_dir() {
        let mut yubi = Yubico::new();

        if let Ok(device) = yubi.find_yubikey() {
            println!(
                "Yubico found: Vendor ID is {:?}, Product ID is {:?}",
                device.vendor_id, device.product_id
            );

            let config = Config::default()
                .set_vendor_id(device.vendor_id)
                .set_product_id(device.product_id)
                .set_variable_size(true)
                .set_mode(Mode::Sha1)
                .set_slot(Slot::Slot2);

            // Challenge can not be greater than 64 bytes
            let challenge = String::from("Keysas-Challenge");
            // In HMAC Mode, the result will always be the SAME for the SAME provided challenge
            match yubi.challenge_response_hmac(challenge.as_bytes(), config) {
                Ok(hmac_result) => {
                    let v: &[u8] = hmac_result.deref();
                    let hex_string = hex::encode(v);

                    let cfg = kvConfig::new("/etc/keysas/yubikey_db");

                    // Open the key/value store
                    match Store::new(cfg) {
                        Ok(store) => match store.bucket::<String, String>(Some("Keysas")) {
                            Ok(enrolled_yubikeys) => {
                                enrolled_yubikeys.get(&hex_string).unwrap().map(|name| name)
                            }
                            Err(why) => {
                                println!("Error while accessing the Bucket: {:?}", why);
                                None
                            }
                        },
                        Err(why) => {
                            println!("Error while accessing the store: {:?}", why);
                            None
                        }
                    }
                }
                Err(why) => {
                    println!("Error while performing hmac challenge {:?}", why);
                    None
                }
            }
        } else {
            println!("Yubikey not found, please insert a Yubikey.");
            None
        }
    } else {
        println!("Error: Database /etc/keysas/yubikey_db wasn't found.");
        None
    }
}

fn get_signature(device: &str) -> Result<String> {
    let offset = 512;
    let mut f = File::options()
        .read(true)
        .open(device)
        .context("Cannot open the USB device to verify the signature.")?;
    let mut buf = vec![0u8; 2048];
    f.seek(SeekFrom::Start(offset))?;
    f.read_exact(&mut buf)?;

    let (i, len) = be_u32::<&[u8], nom::error::Error<&[u8]>>(&buf).map_err(|err| {
        err.map(|err| Error::new(String::from_utf8(err.input.to_vec()), err.code))
    })?;
    let (_, signature) = take::<u32, &[u8], nom::error::Error<&[u8]>>(len)(i).map_err(|err| {
        err.map(|err| Error::new(String::from_utf8(err.input.to_vec()), err.code))
    })?;
    let signature = str::from_utf8(signature)?;
    //    match parser(&bufstr) {
    //        Ok(signature) => {
    //            println!("{}",signature);
    //            signature},
    //        Err(err) => err.to_string(),
    //    };
    Ok(signature.to_string())
}

fn is_signed(
    device: &str,
    pubkey_path: &str,
    id_vendor_id: &str,
    id_model_id: &str,
    id_revision: &str,
    id_serial: &str,
) -> Result<bool> {
    println!("Checking signature for device: {}", device);
    match get_signature(device.remove_last()) {
        Ok(signature) => {
            //println!("Read signature from key: {:?}", signature);
            let pubkey_path = pubkey_path;

            let pk_box_str = fs::read_to_string(pubkey_path)?;
            let signature_box = SignatureBox::from_string(&signature)?;
            // Load the public key from the string.
            let pk_box = PublicKeyBox::from_string(&pk_box_str)?;
            let pk = pk_box.into_public_key()?;
            // And verify the data.
            let data = format!(
                "{}/{}/{}/{}/{}",
                id_vendor_id, id_model_id, id_revision, id_serial, "out"
            );
            println!("{}", data);
            let data_reader = Cursor::new(&data);
            let verified = minisign::verify(&pk, &signature_box, data_reader, true, false, false);
            println!("USB device is signed: {:?}", verified);
            match verified {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
        Err(_) => Ok(false),
    }
}

fn copy_device_in(device: &Path) -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mount_point = dir.path();
    println!(
        "Unsigned USB device {:?} will be mounted on path: {:?}",
        device, mount_point
    );
    let supported = SupportedFilesystems::new()?;
    let mount_result = Mount::builder()
        .fstype(FilesystemType::from(&supported))
        .flags(MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NOEXEC | MountFlags::NODEV)
        .mount(device, mount_point);
    match mount_result {
        Ok(mount) => {
            // Copying file to the mounted device.
            println!("Unsigned device is mounted on: {:?}", mount_point);
            copy_files_in(&mount_point.to_path_buf())?;
            // Make the mount temporary, so that it will be unmounted on drop.
            let _mount = mount.into_unmount_drop(UnmountFlags::DETACH);
        }
        Err(why) => {
            eprintln!("Failed to mount unsigned device: {}", why);
            let reg = Regex::new(r"/tmp/\.tmp.*")?;
            for mount in MountIter::new()? {
                let mnt = mount.as_ref().unwrap().dest.to_str().unwrap();
                if reg.is_match(mnt) {
                    println!("Will umount: {}", mnt);
                }
            }
            //exit(1);
        }
    }
    Ok(())
}

fn move_device_out(device: &Path) -> Result<PathBuf> {
    let dir = tempfile::tempdir()?;
    let mount_point = dir.path();
    println!(
        "Signed USB device {:?} will be mounted on path: {:?}",
        device, mount_point
    );
    let supported = SupportedFilesystems::new()?;
    let mount_result = Mount::builder()
        .fstype(FilesystemType::from(&supported))
        .flags(MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::NODEV)
        .mount(device, mount_point);
    match mount_result {
        Ok(mount) => {
            // Moving files to the mounted device.
            println!("Temporary out mount point: {:?}", mount_point);
            move_files_out(&mount_point.to_path_buf())?;
            // Make the mount temporary, so that it will be unmounted on drop.
            let _mount = mount.into_unmount_drop(UnmountFlags::DETACH);
        }
        Err(why) => {
            eprintln!("Failed to mount device: {}", why);
            //exit(1);
        }
    }
    Ok(mount_point.to_path_buf())
}

fn copy_files_in(mount_point: &PathBuf) -> Result<()> {
    File::create("/var/local/in/.lock")?;
    thread::scope(|s| {
             for e in WalkDir::new(mount_point).into_iter().filter_map(|e| e.ok()) {
                 if e.metadata().expect("Cannot get metadata for file.").is_file() {
             s.spawn(move |_| {
                         println!("New entry path found: {}.", e.path().display());
                         let path_to_read = e.path().to_str().unwrap();
                         //let entry_str = e.path().display();
                         //Replacing any ? in case conversion failed
                         //let path_to_read =
                         //    format!("{}{}{}", &mount_point.to_string_lossy(), "/", &entry_str);
                         let entry = e.file_name().to_string_lossy();
                         let entry_cleaned = str::replace(&entry, "?", "-");
                         let path_to_write = format!(
                             "{}{}",
                             "/var/local/in/",
                             diacritics::remove_diacritics(&entry_cleaned)
                         );
                         let path_to_tmp = format!(
                             "{}{}",
                             "/var/local/tmp/",
                             diacritics::remove_diacritics(&entry_cleaned)
                         );
                         // Create a tmp dir to be able to rename files later
                         let tmp = Path::new("/var/local/tmp/");
                         if !tmp.exists() &&  !tmp.is_dir() {
                             match fs::create_dir(tmp) {
                                 Ok(_)=> println!("Creating tmp directory for writing incoming files !"),
                                 Err(e) => println!("Cannot create tmp directory: {:?}", e),
                             }
                         }
                         match fs::metadata(path_to_read) {
                             Ok(mtdata) => {
                                 if Path::new(&path_to_read).exists() && !mtdata.is_dir() {
                                     match fs::copy(path_to_read, &path_to_tmp) {
                                         Ok(_) => {
                                             println!(
                                             "File {} copied to {}.",
                                             path_to_read, path_to_tmp
                                         );
                                         if fs::rename(&path_to_tmp, path_to_write).is_ok() { println!("File {} moved to sas-in.", &path_to_tmp) }
                                     },
                                         Err(e) => {
                                             println!(
                                                 "Error while copying file {}: {:?}",
                                                 path_to_read, e
                                             );
                                             let mut report =
                                                 format!("{}{}", path_to_write, ".failed");
                                             match File::create(&report) {
                                                 Ok(_) => println!("io-error report file created."),
                                                 Err(why) => {
                                                     eprintln!(
                                                         "Failed to create io-error report {:?}: {}",
                                                         report, why
                                                     );
                                                 }
                                             }
                                             match writeln!(
                                                 report,
                                                 "Error while copying file: {:?}",
                                                 e
                                             ) {
                                                 Ok(_) => println!("io-error report file created."),
                                                 Err(why) => {
                                                     eprintln!(
                                                     "Failed to write into io-error report {:?}: {}",
                                                     report, why
                                                 );
                                                 }
                                             }
                                             match unmount(mount_point, UnmountFlags::DETACH) {
                                                 Ok(()) => {
                                                     println!(
                                                         "Early removing mount point: {:?}",
                                                         mount_point
                                                     )
                                                 }
                                                 Err(why) => {
                                                     eprintln!(
                                                         "Failed to unmount {:?}: {}",
                                                         mount_point, why
                                                     );
                                                 }
                                             }
                                         }
                                     }
                                 }
                             }
                             Err(why) => eprintln!(
                                 "Thread error: Cannot get metadata for file {:?}: {:?}. Terminating thread...",
                                 path_to_read, why
                             ),
                         };
             });
         }
         }
     })
     .expect("Cannot scope threads !");
    println!("Incoming files copied, unlocking.");
    if Path::new("/var/local/in/.lock").exists() {
        fs::remove_file("/var/local/in/.lock")?;
    }
    Ok(())
}

fn move_files_out(mount_point: &PathBuf) -> Result<()> {
    let dir = fs::read_dir("/var/local/out/")?;
    for entry in dir {
        let entry = entry?;
        println!("New entry found: {:?}.", entry.file_name());

        let path_to_write = format!(
            "{}{}{}",
            &mount_point.to_string_lossy(),
            "/",
            diacritics::remove_diacritics(&entry.file_name().to_string_lossy())
        );
        let path_to_read = format!(
            "{}{}",
            "/var/local/out/",
            entry.file_name().to_string_lossy().into_owned()
        );
        if !fs::metadata(&path_to_read)?.is_dir() {
            match fs::copy(&path_to_read, path_to_write) {
                Ok(_) => println!("Copying file: {} to signed device.", path_to_read),
                Err(e) => {
                    println!(
                        "Error while copying file to signed device {}: {:?}",
                        path_to_read, e
                    );
                    match unmount(mount_point, UnmountFlags::DETACH) {
                        Ok(()) => println!("Early removing mount point: {:?}", mount_point),
                        Err(why) => {
                            eprintln!("Failed to unmount {:?}: {}", mount_point, why);
                        }
                    }
                }
            }
            fs::remove_file(&path_to_read)?;
            println!("Removing file: {}.", path_to_read);
        }
    }
    println!("Moving files to out device done.");
    Ok(())
}
fn busy_in() -> Result<(), anyhow::Error> {
    if !Path::new("/var/lock/keysas").exists() {
        create_dir_all("/var/lock/keysas")?;
    } else if Path::new("/var/lock/keysas/keysas-out").exists() {
        fs::remove_file("/var/lock/keysas/keysas-out")?;
    } else if Path::new("/var/lock/keysas/keysas-transit").exists() {
        fs::remove_file("/var/lock/keysas/keysas-transit")?;
    } else if !Path::new("/var/lock/keysas/keysas-in").exists() {
        File::create("/var/lock/keysas/keysas-in")?;
    } else {
    }
    Ok(())
}

fn busy_out() -> Result<(), anyhow::Error> {
    if !Path::new("/var/lock/keysas").exists() {
        create_dir_all("/var/lock/keysas")?;
    } else if Path::new("/var/lock/keysas/keysas-in").exists() {
        fs::remove_file("/var/lock/keysas/keysas-in")?;
    } else if Path::new("/var/lock/keysas/keysas-transit").exists() {
        fs::remove_file("/var/lock/keysas/keysas-transit")?;
    } else if !Path::new("/var/lock/keysas/keysas-out").exists() {
        File::create("/var/lock/keysas/keysas-out")?;
    } else {
    }
    Ok(())
}

fn ready_in() -> Result<(), anyhow::Error> {
    if Path::new("/var/lock/keysas/keysas-in").exists() {
        fs::remove_file("/var/lock/keysas/keysas-in")?;
    }
    Ok(())
}

fn ready_out() -> Result<(), anyhow::Error> {
    if Path::new("/var/lock/keysas/keysas-out").exists() {
        fs::remove_file("/var/lock/keysas/keysas-out")?;
    }
    Ok(())
}

fn get_attr_udev(event: Event) -> Result<String, anyhow::Error> {
    let id_vendor_id = event
        .property_value(
            OsStr::new("ID_VENDOR_ID")
                .to_str()
                .ok_or_else(|| anyhow!("Cannot convert ID_VENDOR_ID to str."))?,
        )
        .ok_or_else(|| anyhow!("Cannot get ID_VENDOR_ID from event."))?;
    let id_model_id = event
        .property_value(
            OsStr::new("ID_MODEL_ID")
                .to_str()
                .ok_or_else(|| anyhow!("Cannot convert ID_MODEL_ID to str."))?,
        )
        .ok_or_else(|| anyhow!("Cannot get ID_MODEL_ID from event."))?;
    let id_revision = event
        .property_value(
            OsStr::new("ID_REVISION")
                .to_str()
                .ok_or_else(|| anyhow!("Cannot convert ID_REVISION to str."))?,
        )
        .ok_or_else(|| anyhow!("Cannot get ID_REVISION from event."))?;

    let product = format!(
        "{}/{}/{}",
        id_vendor_id.to_string_lossy(),
        id_model_id.to_string_lossy(),
        id_revision.to_string_lossy()
    );
    Ok(product)
}

fn main() -> Result<()> {
    let matches = Clap_Command::new("keysas-io")
        .version(crate_version!())
        .author("Stephane N")
        .about("keysas-io for USB devices verification.")
        .arg(
            Arg::new("pubkey")
                .short('p')
                .long("pubkey")
                .value_name("/path/to/public.pub")
                .value_parser(clap::value_parser!(String))
                .default_value("/etc/keysas/keysas.pub")
                .help("The path to public key (Default is /etc/keysas/keysas.pub)."),
        )
        .arg(
            Arg::new("yubikey")
                .short('y')
                .long("yubikey")
                .value_name("false")
                .default_value("false")
                .value_parser(clap::value_parser!(String))
                .help("Activate the user authentication via Yubikeys."),
        )
        .get_matches();

    let pubkey = matches.get_one::<String>("pubkey").unwrap();
    let pubkey_path = pubkey.to_string();
    let pubkey_path = Arc::new(pubkey_path);
    let yubikey = matches.get_one::<String>("yubikey").unwrap();
    let yubikey = yubikey
        .parse::<bool>()
        .context("Cannot convert YUBIKEY value string into boolean !")?;

    let server = TcpListener::bind("127.0.0.1:3013")?;
    for stream in server.incoming() {
        let pubkey_path = Arc::clone(&pubkey_path);
        spawn(move || -> Result<()> {
            let callback = |_req: &Request, response: Response| {
                println!("keysas-udev: Received a new websocket handshake.");
                //println!("The request's path is: {}", req.uri().path());
                //println!("The request's headers are:");
                //for (ref header, _value) in req.headers() {
                //    println!("* {}", header);
                //}

                // Let's add an additional header to our response to the client.
                //let headers = response.headers_mut();
                //headers.append("keysas-udev", "true".parse().unwrap());

                Ok(response)
            };
            let mut websocket = accept_hdr(stream?, callback)?;

            let socket = udev::MonitorBuilder::new()?
                .match_subsystem("block")?
                .listen()?;

            let mut fds = vec![pollfd {
                fd: socket.as_raw_fd(),
                events: POLLIN,
                revents: 0,
            }];
            let mut keys_in = vec![];
            let mut keys_out = vec![];
            let mut keys_undef = vec![];
            let yubi: Yubistruct = Yubistruct {
                active: yubikey,
                yubikeys: list_yubikey(),
            };
            let keys: Usbkeys = Usbkeys {
                usb_in: Vec::new(),
                usb_out: Vec::new(),
                usb_undef: Vec::new(),
                yubikeys: yubi,
            };
            let serialized = serde_json::to_string(&keys)?;
            websocket.write_message(Message::Text(serialized))?;

            loop {
                let result = unsafe {
                    ppoll(
                        fds[..].as_mut_ptr(),
                        fds.len() as nfds_t,
                        ptr::null_mut(),
                        ptr::null(),
                    )
                };

                if result < 0 {
                    println!("Error: ppoll error, result is < 0.");
                }

                let event = match socket.iter().next() {
                    Some(evt) => evt,
                    None => {
                        sthread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };

                //println!("Event: {:?}", event.event_type());
                if event.action() == Some(OsStr::new("add"))
                    && event.property_value(
                        OsStr::new("DEVTYPE")
                            .to_str()
                            .ok_or_else(|| anyhow!("Cannot convert DEVTYPE to str."))?,
                    ) == Some(OsStr::new("partition"))
                {
                    let yubi: Yubistruct = Yubistruct {
                        active: yubikey,
                        yubikeys: list_yubikey(),
                    };
                    let keys: Usbkeys = Usbkeys {
                        usb_in: Vec::new(),
                        usb_out: Vec::new(),
                        usb_undef: Vec::new(),
                        yubikeys: yubi,
                    };
                    let serialized = serde_json::to_string(&keys)?;
                    websocket.write_message(Message::Text(serialized))?;

                    let id_vendor_id = event
                        .property_value(
                            OsStr::new("ID_VENDOR_ID")
                                .to_str()
                                .ok_or_else(|| anyhow!("Cannot convert ID_VENDOR_ID to str."))?,
                        )
                        .ok_or_else(|| anyhow!("Cannot get ID_VENDOR_ID from event."))?;
                    let id_model_id = event
                        .property_value(
                            OsStr::new("ID_MODEL_ID")
                                .to_str()
                                .ok_or_else(|| anyhow!("Cannot convert ID_MODEL_ID to str."))?,
                        )
                        .ok_or_else(|| anyhow!("Cannot get ID_MODEL_ID from event."))?;
                    let id_revision = event
                        .property_value(
                            OsStr::new("ID_REVISION")
                                .to_str()
                                .ok_or_else(|| anyhow!("Cannot convert ID_REVISION to str."))?,
                        )
                        .ok_or_else(|| anyhow!("Cannot get ID_REVISION from event."))?;
                    let device = event
                        .property_value(
                            OsStr::new("DEVNAME")
                                .to_str()
                                .ok_or_else(|| anyhow!("Cannot get DEVNAME from event."))?,
                        )
                        .ok_or_else(|| anyhow!("Cannot get DEVNAME from event."))?;
                    let id_serial = event
                        .property_value(
                            OsStr::new("ID_SERIAL")
                                .to_str()
                                .ok_or_else(|| anyhow!("Cannot convert ID_SERIAL to str."))?,
                        )
                        .ok_or_else(|| anyhow!("Cannot get ID_SERIAL from event."))?;
                    //println!("device: {:?}", event.device().parent().unwrap().property_value(OsStr::new("system_name")));
                    //for property in event.device().parent() {
                    //    for attr in property.attributes() {
                    //        println!("{:?}:{:?}", attr.name(),attr.value());
                    //        //println!("{:?} = {:?}", property.name(), property.value());
                    //}
                    //    }
                    println!("New USB device found: {}", device.to_string_lossy());
                    let product = format!(
                        "{}/{}/{}",
                        id_vendor_id.to_string_lossy(),
                        id_model_id.to_string_lossy(),
                        id_revision.to_string_lossy()
                    );

                    let id_vendor_id = id_vendor_id
                        .to_str()
                        .ok_or_else(|| anyhow!("Cannot convert id_vendor_id to str."))?;
                    let id_model_id = id_model_id
                        .to_str()
                        .ok_or_else(|| anyhow!("Cannot convert id_model_id to str."))?;
                    let id_revision = id_revision
                        .to_str()
                        .ok_or_else(|| anyhow!("Cannot convert id_revision to str."))?;
                    let device = device
                        .to_str()
                        .ok_or_else(|| anyhow!("Cannot convert device to str."))?;
                    let id_serial = id_serial
                        .to_str()
                        .ok_or_else(|| anyhow!("Cannot convert id_serial to str."))?;

                    let signed = is_signed(
                        device,
                        &pubkey_path,
                        id_vendor_id,
                        id_model_id,
                        id_revision,
                        id_serial,
                    );
                    match signed {
                        Ok(value) => {
                            //Invalid Signature
                            println!("Value is {}", value);
                            if !value {
                                println!("Device signature is not valid !");
                                let keys_in_iter: Vec<String> =
                                    keys_in.clone().into_iter().collect();
                                if !keys_in_iter.contains(&product) {
                                    busy_in()?;
                                    keys_in.push(product);
                                    let yubi: Yubistruct = Yubistruct {
                                        active: yubikey,
                                        yubikeys: list_yubikey(),
                                    };
                                    let keys: Usbkeys = Usbkeys {
                                        usb_in: keys_in.clone(),
                                        usb_out: keys_out.clone(),
                                        usb_undef: keys_undef.clone(),
                                        yubikeys: yubi,
                                    };
                                    let serialized = serde_json::to_string(&keys)?;
                                    websocket.write_message(Message::Text(serialized))?;
                                    if yubikey {
                                        match hmac_challenge() {
                                            Some(name) => {
                                                println!(
                                                    "HMAC challenge successfull for user: {} !",
                                                    name
                                                );
                                                copy_device_in(Path::new(&device))?;
                                                println!("Unsigned USB device done.");
                                                ready_in()?;
                                            }
                                            None => {
                                                println!("No user found during HMAC challenge !");
                                                ready_in()?;
                                            }
                                        };
                                    } else {
                                        copy_device_in(Path::new(&device))?;
                                        println!("Unsigned USB device done.");
                                        ready_in()?;
                                    }
                                }
                            //Signature ok so this is a out device
                            } else if value {
                                println!("USB device is signed...");
                                let keys_out_iter: Vec<String> =
                                    keys_out.clone().into_iter().collect();
                                if !keys_out_iter.contains(&product) {
                                    busy_out()?;
                                    keys_out.push(product);
                                    let yubi: Yubistruct = Yubistruct {
                                        active: yubikey,
                                        yubikeys: list_yubikey(),
                                    };
                                    let keys: Usbkeys = Usbkeys {
                                        usb_in: keys_in.clone(),
                                        usb_out: keys_out.clone(),
                                        usb_undef: keys_undef.clone(),
                                        yubikeys: yubi,
                                    };
                                    let serialized = serde_json::to_string(&keys)?;
                                    websocket
                                        .write_message(Message::Text(serialized))
                                        .expect("bunbun");
                                    move_device_out(Path::new(&device))?;
                                    println!("Signed USB device done.");
                                    ready_out()?;
                                }
                            } else {
                                let keys_undef_iter: Vec<String> =
                                    keys_undef.clone().into_iter().collect();
                                if !keys_undef_iter.contains(&product) {
                                    keys_undef.push(product);
                                    println!("Undefined USB device.");
                                    let yubi: Yubistruct = Yubistruct {
                                        active: yubikey,
                                        yubikeys: list_yubikey(),
                                    };
                                    let keys: Usbkeys = Usbkeys {
                                        usb_in: keys_in.clone(),
                                        usb_out: keys_out.clone(),
                                        usb_undef: keys_undef.clone(),
                                        yubikeys: yubi,
                                    };
                                    let serialized = serde_json::to_string(&keys)?;
                                    websocket.write_message(Message::Text(serialized))?;
                                }
                            }
                        }
                        Err(e) => {
                            println!("USB device never signed: {}", e);
                            let keys_in_iter: Vec<String> = keys_in.clone().into_iter().collect();
                            if !keys_in_iter.contains(&product) {
                                // busy_in ?
                                busy_in()?;
                                keys_in.push(product);
                                let yubi: Yubistruct = Yubistruct {
                                    active: yubikey,
                                    yubikeys: list_yubikey(),
                                };
                                let keys: Usbkeys = Usbkeys {
                                    usb_in: keys_in.clone(),
                                    usb_out: keys_out.clone(),
                                    usb_undef: keys_undef.clone(),
                                    yubikeys: yubi,
                                };
                                let serialized = serde_json::to_string(&keys)?;
                                websocket.write_message(Message::Text(serialized))?;
                                if yubikey {
                                    match hmac_challenge() {
                                        Some(name) => {
                                            println!(
                                                "HMAC challenge successfull for user: {} !",
                                                name
                                            );
                                            copy_device_in(Path::new(&device))?;
                                            println!("Unsigned USB device done.");
                                            ready_in()?;
                                        }
                                        None => println!("No user found during HMAC challenge !"),
                                    };
                                } else {
                                    copy_device_in(Path::new(&device))?;
                                    println!("Unsigned USB device done.");
                                    ready_in()?;
                                }
                            }
                        }
                    };
                } else if event.action() == Some(OsStr::new("remove")) {
                    let product = match get_attr_udev(event) {
                        Ok(product) => product,
                        Err(_) => String::from("unknown"),
                    };

                    if product.contains("unknown") {
                        keys_in.clear();
                        keys_out.clear();
                    } else {
                        keys_out.retain(|x| *x != product);
                        keys_in.retain(|x| *x != product);
                        keys_undef.retain(|x| *x != product);
                    }
                    let yubi: Yubistruct = Yubistruct {
                        active: yubikey,
                        yubikeys: list_yubikey(),
                    };
                    let keys: Usbkeys = Usbkeys {
                        usb_in: keys_in.clone(),
                        usb_out: keys_out.clone(),
                        usb_undef: keys_undef.clone(),
                        yubikeys: yubi,
                    };

                    let serialized = serde_json::to_string(&keys)?;
                    websocket.write_message(Message::Text(serialized))?;
                }

                sthread::sleep(Duration::from_millis(60));
            }
        });
    }
    Ok(())
}
