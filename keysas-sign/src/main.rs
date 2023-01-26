// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-sign".
 *
 * (C) Copyright 2019-2023 Stephane Neveu
 *
 * The code for keysas-sign binary.
 */

use anyhow::anyhow;
use clap::{crate_version, Arg, ArgAction, Command};
use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use std::fs::remove_file;
use std::fs::File;
use std::io;
use std::io::prelude::*;
use std::io::SeekFrom;
use std::path::Path;
extern crate minisign;
use minisign::{KeyPair, PublicKeyBox, SecretKeyBox, SignatureBox};
use std::io::Cursor;
mod errors;
use crate::errors::*;
use std::fs;
extern crate libc;
extern crate udev;
use libc::{c_int, c_short, c_ulong, c_void};
use nom::error::Error;
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::io::AsRawFd;
use std::process;
use std::process::Command as Cmd;
use std::ptr;
use std::str;
use std::thread;
use std::time::Duration;

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

fn info(device: &str) -> Result<()> {
    let mut f = std::fs::File::open(device).context("could not open disk")?;
    let mbr = mbrman::MBR::read_from(&mut f, 512).context("could not find MBR")?;
    println!("MBR disk signature: {:?}", mbr.header.disk_signature);

    for (i, p) in mbr.iter() {
        if p.is_used() {
            println!(
                "Partition #{}: type = {:?}, sectors= {}, sector_size= {}, starting lba = {}",
                i, p.sys, p.sectors, mbr.sector_size, p.starting_lba
            );
        }
    }
    Ok(())
}

// Remove the partition number and return the device
// TODO: manage when partition >= 10
fn rm_last(value: &str) -> &str {
    let chars = value.chars();
    let mut tmp = chars.clone();
    match chars.last() {
        Some(last) => {
            if last.is_numeric() {
                tmp.next_back();
                return tmp.as_str();
            } else {
                return tmp.as_str();
            }
        }
        None => value,
    }
}

fn get_signature(device: &str) -> Result<String> {
    let offset = 512;
    let mut f = File::options()
        .read(true)
        .open(device)
        .context("Cannot open device.")?;
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

fn signme(
    vendor: &str,
    model: &str,
    revision: &str,
    serial: &str,
    direction: &str,
    privkey_path: &str,
    password: &str,
) -> Result<String> {
    let sk_box_str = fs::read_to_string(privkey_path)?;
    let sk_box = SecretKeyBox::from_string(&sk_box_str)?;

    // and the box can be opened using the password to reveal the original secret key:
    let sk = sk_box.into_secret_key(Some(password.to_string()))?;

    // Now, we can use the secret key to sign anything.
    let data = format!("{vendor}/{model}/{revision}/{serial}/{direction}");
    let data_reader = Cursor::new(&data);
    let signature_box = minisign::sign(
        None,
        &sk,
        data_reader,
        Some(&data),
        Some("Signature from Keysas secret"),
    )?;

    // Converting the signature box to a string in order to save it is easy.
    Ok(signature_box.into_string())
}

fn watch() -> Result<()> {
    let socket = udev::MonitorBuilder::new()?
        //.match_subsystem_devtype("usb", "usb_device")?
        .match_subsystem("block")?
        .listen()?;

    let mut fds = vec![pollfd {
        fd: socket.as_raw_fd(),
        events: POLLIN,
        revents: 0,
    }];
    println!("Watching... you can plug your device in !");

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
            println!("Error: result is < 0.");
        }

        let event = match socket.iter().next() {
            Some(evt) => evt,
            None => {
                thread::sleep(Duration::from_millis(5));
                continue;
            }
        };

        for _property in event.properties() {
            if event.action() == Some(OsStr::new("add"))
                && event.property_value(
                    OsStr::new("DEVTYPE")
                        .to_str()
                        .ok_or_else(|| anyhow!("Cannot convert DEVTYPE to str."))?,
                ) == Some(OsStr::new("partition"))
            {
                let dev = event.device();
                let device = dev.devnode().unwrap();
                let dev = &device.to_string_lossy();
                let device = rm_last(dev);

                let vendor = event
                    .property_value(
                        OsStr::new("ID_VENDOR_ID")
                            .to_str()
                            .ok_or_else(|| anyhow!("Cannot convert ID_VENDOR_ID to str."))?,
                    )
                    .ok_or_else(|| anyhow!("Cannot get ID_VENDOR_ID from event."))?;
                let model = event
                    .property_value(
                        OsStr::new("ID_MODEL_ID")
                            .to_str()
                            .ok_or_else(|| anyhow!("Cannot convert ID_MODEL_ID to str."))?,
                    )
                    .ok_or_else(|| anyhow!("Cannot get ID_MODEL_ID from event."))?;
                let revision = event
                    .property_value(
                        OsStr::new("ID_REVISION")
                            .to_str()
                            .ok_or_else(|| anyhow!("Cannot convert ID_REVISION to str."))?,
                    )
                    .ok_or_else(|| anyhow!("Cannot get ID_REVISION from event."))?;
                let serial = event
                    .property_value(
                        OsStr::new("ID_SERIAL")
                            .to_str()
                            .ok_or_else(|| anyhow!("Cannot convert ID_SERIAL to str."))?,
                    )
                    .ok_or_else(|| anyhow!("Cannot get ID_SERIAL from event."))?;
                println!(
                    "Found key: Vendor: {}, Model: {}, Revision: {}, Serial: {}",
                    vendor.to_string_lossy(),
                    model.to_string_lossy(),
                    revision.to_string_lossy(),
                    serial.to_string_lossy()
                );
                println!(
                    "To sign your new USB-OUT key, type the following with your own password:"
                );
                println!("keysas-sign --device={} --sign --password=YourSecretPassWord --vendorid={} --modelid={} --revision={} --serial={}", device ,vendor.to_string_lossy() ,model.to_string_lossy(), revision.to_string_lossy(), serial.to_string_lossy());
                process::exit(0);
            }
        }
    }
}

fn try_format(device: &str) -> Result<()> {
    println!("Formating USB device...");
    Cmd::new("/usr/sbin/mkfs.vfat").arg(device).spawn()?;
    println!("USB device formated to vfat !");
    println!(
        "(If it failed, you can format manually the newly created partition. Run 'mkfs.vfat {}1')",
        device
    );
    Ok(())
}

fn sign_usb(
    device: &str,
    vendor: &str,
    model: &str,
    revision: &str,
    serial: &str,
    direction: &str,
    privkey_path: &str,
    password: &str,
) -> Result<()> {
    println!("Let's start signing the new out-key !");
    let mut f = File::options()
        .write(true)
        .read(true)
        .open(device)
        .context("Cannot open device for signing.")?;

    let ss = 512;
    let mut mbr = mbrman::MBR::new_from(&mut f, ss as u32, [0x00, 0x0A, 0x0B, 0x0C])
        .context("Could not make a partition table")?;
    let sectors = mbr
        .get_maximum_partition_size()
        .context("No more space available in the USB device")?;

    let starting_lba_i32 = 2048;
    let starting_lba = starting_lba_i32 as u32;

    mbr[1] = mbrman::MBRPartitionEntry {
        boot: mbrman::BOOT_INACTIVE,     // boot flag
        first_chs: mbrman::CHS::empty(), // first CHS address (only useful for old computers)
        sys: 0x0c,                       // fat32+ LBA filesystem
        last_chs: mbrman::CHS::empty(),  // last CHS address (only useful for old computers)
        starting_lba,                    // the sector where the partition starts
        sectors,                         // the number of sectors in that partition
    };

    // actually writes the new partition Entry:
    mbr.write_into(&mut f)
        .context("Could not write MBR to disk")?;

    //Let's write behind the magic number now
    let offset = 512;
    let attrs = signme(
        vendor,
        model,
        revision,
        serial,
        direction,
        privkey_path,
        password,
    )?;
    let size_u32 = attrs.len() as u32;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&size_u32.to_be_bytes())?;
    f.write_all(attrs.as_bytes())?;
    println!("USB device is now signed successfully ! :)");
    Ok(())
}

fn revoke_usb(device: &str) -> Result<()> {
    println!("Let's start signing the new out-key !");
    let mut f = File::options()
        .write(true)
        .read(true)
        .open(device)
        .context("Cannot open device for revoking.")?;

    //Let's write behind the magic number now
    let offset = 512;
    let blank: String = String::from("0000000");
    let size_u32 = blank.len() as u32;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(&size_u32.to_be_bytes())?;
    f.write_all(blank.as_bytes())?;
    println!("USB device is now signed successfully ! :)");
    Ok(())
}

fn main() -> Result<()> {
    // Start clap CLI definition
    let matches = Command::new("keysas-sign")
        .version(crate_version!())
        .author("Stephane N")
        .about("Keysas tool for USB devices signature & verification.")
        .arg(
            Arg::new("device")
                .short('d')
                .long("device")
                .value_name("/dev/sdX")
                .help("Sets the path to device (Default is /dev/sda)")
                .default_value("/dev/sda")
                .conflicts_with("generate")
                .conflicts_with("watch"),
        )
        .arg(
            Arg::new("generate")
                .short('g')
                .long("generate")
                .value_name("true/false")
                .help("Generate a keypair for signing purpose (Default is false).")
                .default_value("false")
                //.value_parser(clap::value_parser!(bool))
                .action(ArgAction::SetTrue)
                .requires("password")
                .conflicts_with("watch")
                .conflicts_with("vendor")
                .conflicts_with("model")
                .conflicts_with("revision")
                .conflicts_with("verify")
                .conflicts_with("sign"),
        )
        .arg(
            Arg::new("sign")
                .short('s')
                .long("sign")
                .value_name("true/false")
                .help("Sign the USB device (Default is false).")
                .default_value("false")
                //.value_parser(clap::value_parser!(bool))
                .action(ArgAction::SetTrue)
                .requires("vendor")
                .requires("model")
                .requires("revision")
                .requires("password")
                .requires("device")
                .conflicts_with("watch")
                .conflicts_with("verify")
                .conflicts_with("generate"),
        )
        .arg(
            Arg::new("verify")
                .short('y')
                .long("verify")
                .value_name("true/false")
                .help("Verify the USB device (Default is false).")
                //.takes_value(true)
                .default_value("false")
                //.value_parser(clap::value_parser!(bool))
                .action(ArgAction::SetTrue)
                .requires("vendor")
                .requires("model")
                .requires("revision")
                .requires("device")
                .conflicts_with("watch")
                .conflicts_with("sign")
                .conflicts_with("generate"),
        )
        .arg(
            Arg::new("watch")
                .short('w')
                .long("watch")
                .value_name("true/false")
                .help("Watch a new USB device (Default is true).")
                //.takes_value(true)
                .default_value("false")
                //.value_parser(clap::value_parser!(bool))
                .action(ArgAction::SetTrue)
                .conflicts_with("generate")
                .conflicts_with("vendor")
                .conflicts_with("model")
                .conflicts_with("revision")
                .conflicts_with("verify")
                .conflicts_with("sign")
                .conflicts_with("revoke"),
        )
        .arg(
            Arg::new("revoke")
                .short('o')
                .long("revoke")
                .value_name("true/false")
                .help("Revoke a USB device (Default is false).")
                //.takes_value(true)
                .default_value("false")
                //.value_parser(clap::value_parser!(bool))
                .action(ArgAction::SetTrue)
                .requires("device")
                .conflicts_with("generate")
                .conflicts_with("vendor")
                .conflicts_with("model")
                .conflicts_with("revision")
                .conflicts_with("verify")
                .conflicts_with("sign")
                .conflicts_with("watch"),
        )
        .arg(
            Arg::new("password")
                .short('p')
                .long("password")
                .value_name("PASSWORD")
                .help("The password for private key (Default is 'Changeme007'). It must be changed of course.")
                .default_value("Changeme007")
                //.takes_value(true)
                //.requires("sign")
                //.requires("verify")
                .conflicts_with("watch"),
        )
        .arg(
            Arg::new("privkey")
                .short('k')
                .long("privkey")
                .value_name("/path/to/private.key")
                .help("The path to private key (Default is /etc/keysas/keysas.priv).")
                .default_value("/etc/keysas/keysas.priv")
                //.takes_value(true),
        )
        .arg(
            Arg::new("pubkey")
                .short('c')
                .long("pubkey")
                .value_name("/path/to/public.pub")
                .help("The path to public key (Default is /etc/keysas/keysas.pub).")
                .default_value("/etc/keysas/keysas.pub")
                //.takes_value(true),
        )
        .arg(
            Arg::new("vendor")
                .short('v')
                .long("vendorid")
                .value_name("VENDOR_ID")
                .help("The ID_VENDOR_ID of the USB device.")
                //.takes_value(true)
                .default_value("0000")
                .conflicts_with("watch")
                .conflicts_with("generate"),

        )
        .arg(
            Arg::new("model")
                .short('m')
                .long("modelid")
                .value_name("MODEL_ID")
                .help("The ID_MODEL_ID of the USB device.")
                //.takes_value(true)
                .default_value("0000")
                .conflicts_with("watch")
                .conflicts_with("generate"),
        )
        //        .arg(
        //            Arg::new("direction")
        //                .short('z')
        //                .long("direction")
        //               .value_name("DIRECTION")
        //               .about("Value can be either in or out.")
        //               .takes_value(true),
        //        )
        .arg(
            Arg::new("revision")
                .short('r')
                .long("revision")
                .value_name("REVISION")
                .help("The ID_REVISION of the USB device.")
                //.takes_value(true)
                .default_value("0000")
                .conflicts_with("watch")
                .conflicts_with("generate"),
        )
        .arg(
            Arg::new("serial")
                .short('l')
                .long("serial")
                .value_name("SERIAL")
                .help("The ID_SERIAL of the USB device.")
                //.takes_value(true)
                .default_value("0000")
                .conflicts_with("watch")
                .conflicts_with("generate"),
        )
        .arg(
            Arg::new("force")
                .short('f')
                .long("force")
                .value_name("force")
                //.value_parser(clap::value_parser!(bool))
                .action(ArgAction::SetTrue)
                .help("Force signing without any warning.")
                //.takes_value(true)
                .default_value("false")
                .conflicts_with("generate")
                .conflicts_with("verify")
                .conflicts_with("watch"),
        )
        .get_matches();

    let device = matches.get_one::<String>("device").unwrap();
    //let _fstype: &str = matches.get_one::<String>("fstype").unwrap_or("vfat");
    let password = matches.get_one::<String>("password").unwrap();
    let pubkey_path = matches.get_one::<String>("pubkey").unwrap();
    let privkey_path = matches.get_one::<String>("privkey").unwrap();
    let vendor = matches.get_one::<String>("vendor").unwrap();
    let model: &str = matches.get_one::<String>("model").unwrap();
    let revision: &str = matches.get_one::<String>("revision").unwrap();
    let serial: &str = matches.get_one::<String>("serial").unwrap();
    let generate = matches.get_flag("generate");
    let sign = matches.get_flag("sign");
    let verify = matches.get_flag("verify");
    let direction: &str = "out";
    let watchusb = matches.get_flag("watch");
    let force = matches.get_flag("force");
    let revoke = matches.get_flag("revoke");

    if direction == "in" || direction == "out" {
    } else {
        panic!("You must choose either in or out for the key direction.")
    }

    if watchusb {
        watch()?;
    }
    if revoke {
        revoke_usb(device)?;
    }

    if generate {
        println!("Generating keypair!");
        // Generate and return a new key pair
        // The key is encrypted using a password.
        // If `None` is given, the password will be asked for interactively.
        let _output = File::create(privkey_path).context("Cannot create private key file.")?;
        let _output = File::create(pubkey_path).context("Cannot create public key file.")?;

        let private_key = File::options().write(true).read(true).open(privkey_path)?;
        let public_key = File::options().write(true).read(true).open(pubkey_path)?;

        let KeyPair { pk: _, sk: _ } = KeyPair::generate_and_write_encrypted_keypair(
            public_key,
            private_key,
            Some("Keysas-USB-privkey"),
            Some(password.to_string()),
        )?;
        println!("Private key path is: {privkey_path}");
        println!("Public key path is: {pubkey_path}");
        println!("All done.")
    }
    if verify {
        info(device)?;

        match get_signature(device) {
            Ok(signature) => {
                println!("Read signature from key: {signature:?}");
                let pk_box_str = fs::read_to_string(pubkey_path)?;
                let signature_box = SignatureBox::from_string(&signature)?;
                // Load the public key from the string.
                let pk_box = PublicKeyBox::from_string(&pk_box_str)?;
                let pk = pk_box.into_public_key()?;
                // And verify the data.
                let data = format!("{vendor}/{model}/{revision}/{serial}/{direction}");
                let data_reader = Cursor::new(&data);
                let verified =
                    minisign::verify(&pk, &signature_box, data_reader, true, false, false);
                match verified {
                    Ok(()) => println!("Successfully verified your device signature :)"),
                    Err(e) => println!("Verification of the device failed :/ : {e:?}"),
                }
            }
            Err(e) => {
                println!("No signature found on this device: {e}.")
            }
        };
    }
    if sign {
        println!("Warning: All data on the device will be lost ! Are you sure ? (yes/no)");
        let mut buffer = String::new();
        if force {
            buffer = "yes\n".to_string();
        } else {
            io::stdin().read_line(&mut buffer)?;
        }
        if buffer == "yes\n" {
            sign_usb(
                device,
                vendor,
                model,
                revision,
                serial,
                direction,
                privkey_path,
                password,
            )?;
            try_format(device)?;
            if Path::new("/usr/share/keysas/neversigned").exists()
                && Path::new("/usr/share/keysas/neversigned").is_file()
            {
                remove_file("/usr/share/keysas/neversigned")?;
            }
        } else {
            println!("Aborting !");
        }
    }
    Ok(())
}
