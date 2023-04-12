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
 
 // Remove the partition number and return the device
 // TODO: manage if nb partition >= 10
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
     let data = format!("{}/{}/{}/{}/{}", vendor, model, revision, serial, direction);
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
 
 fn watch() -> Result<String> {
     let socket = udev::MonitorBuilder::new()?
         //.match_subsystem_devtype("usb", "usb_device")?
         .match_subsystem("block")?
         .listen()?;
 
     let mut fds = vec![pollfd {
         fd: socket.as_raw_fd(),
         events: POLLIN,
         revents: 0,
     }];
     log::debug!("Watching... you can plug your device in !");
 
     loop {
         let result = unsafe {
             ppoll(
                 (&mut fds[..]).as_mut_ptr(),
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
                 //println!("keysas-sign --device={} --sign --password=YourSecretPassWord --vendorid={} --modelid={} --revision={} --serial={}", device ,vendor.to_string_lossy() ,model.to_string_lossy(), revision.to_string_lossy(), serial.to_string_lossy());
                 let information = format!("New USB device found: Vendor ID: {}, Model ID: {}, Revision: {}, Serial number: {}", vendor.to_string_lossy() ,model.to_string_lossy(), revision.to_string_lossy(), serial.to_string_lossy());
                 Ok(information)
             }
         }
     }
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
     log::debug!("Let's start signing the new out-key !");
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
 
     let starting_lba_i32 = 4096;
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
     log::info!("USB device is now signed successfully.");
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
     log::info!("USB device is now signed successfully.");
     Ok(())
 }
 