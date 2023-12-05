// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! USB monitor implementation for Linux

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

use std::{
    sync::{Arc, Mutex},
    thread,
    io::{self, Read, Seek, SeekFrom},
    time::Duration,
    ptr,
    os::fd::AsRawFd,
    ffi::{OsStr, OsString},
    fs::{read_to_string, File}
};
use libc::{c_int, c_short, c_ulong, c_void};
use udev::{MonitorBuilder, Event};
use anyhow::anyhow;

use crate::usb_monitor::UsbMonitor;
use crate::controller::{ServiceController, UsbDevice};

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

#[derive(Debug, Copy, Clone)]
pub struct LinuxUsbMonitor {}

impl LinuxUsbMonitor {
    pub fn init() -> Result<LinuxUsbMonitor, anyhow::Error> {
        Ok(LinuxUsbMonitor {})
    }
}

/// Get the mount point of a device node
///
/// # Argument
///
/// `devnode` - Device node path, e.g "/dev/sda1"
fn get_mount_point(devnode: &OsStr) -> Result<OsString, anyhow::Error> {
    let mnt_points = read_to_string("/proc/mounts")?;

    for line in mnt_points.lines() {
        let mut tokens = line.split_ascii_whitespace();
        if let Some(node) = tokens.next(){
            if node.eq(devnode) {
                let mnt = tokens.next().ok_or(anyhow!("failed to parse mounts file"))?;
                return Ok(OsString::from(mnt))
            }
        }
    }

    Err(anyhow!("Mount point not found"))
}

/// Extract the information about a USB device and its signature if it exists
///
/// # Argument
///
/// `event` - the udev event associated to the USB device connection
fn extract_usb_info(event: Event) -> Result<(UsbDevice, Option<String>), anyhow::Error> {
    // Extract Usb device metadata
    let device = event.device();

    let devnode = device.devnode().ok_or_else(|| anyhow!("Devnode not found"))?;

    let vendor = device.property_value(OsStr::new("ID_VENDOR_ID"))
                    .ok_or_else(|| anyhow!("Vendor ID not found"))?;
    let model = device.property_value(OsStr::new("ID_MODEL_ID"))
                    .ok_or_else(|| anyhow!("Model ID not found"))?;
    let revision = device.property_value(OsStr::new("ID_REVISION"))
                    .ok_or_else(|| anyhow!("Revision not found"))?;
    let serial = device.property_value(OsStr::new("ID_SERIAL"))
                    .ok_or_else(|| anyhow!("Serial number not found"))?;

    let usb_device = UsbDevice {
        device_id: devnode.as_os_str().to_os_string(),
        mnt_point: None, // Partition not mounted yet
        vendor: vendor.to_os_string(),
        model: model.to_os_string(),
        revision: revision.to_os_string(),
        serial: serial.to_os_string()
    };

    // Try to extract a signature
    let mut f = File::open(devnode)?;
    // First get the signature size
    let mut size_buf = [0u8; 4];
    f.seek(SeekFrom::Start(512))?;
    f.read_exact(&mut size_buf)?;
    let sig_size = u32::from_be_bytes(size_buf);
    // Size must not be greater than 7684 bytes LBA-MBR (8196-512)
    let signature = match sig_size <= 7684 {
        true => {
            let mut sig_buf = vec![0u8; sig_size as usize];
            f.read_exact(&mut sig_buf)?;
            Some(String::from_utf8(sig_buf.to_vec())?)
        },
        false => {
            None
        }
    };

    Ok((usb_device, signature))
}

impl UsbMonitor for LinuxUsbMonitor {
    fn start(&self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error> {
        // Spawn a new thread to monitor udev
        let ctrl_hdl = ctrl.clone();
        thread::spawn(move || -> Result<(), anyhow::Error> {
            // Look for usb device
            let monitor = MonitorBuilder::new()?
                            .match_subsystem("block")?
                            .listen()?;

            let mut fds = vec![pollfd {
                fd: monitor.as_raw_fd(),
                events: POLLIN,
                revents: 0,
            }];

            // Loop over USB events
            loop {
                let res = unsafe {
                    ppoll(
                        (&mut fds[..]).as_mut_ptr(),
                        fds.len() as nfds_t,
                        ptr::null_mut(),
                        ptr::null(),
                    )
                };

                if res < 0 {
                    return Err(anyhow!("ppol error: {}",
                                        io::Error::last_os_error()));
                }

                let event = match monitor.iter().next() {
                    Some(evt) => evt,
                    None => {
                        thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                };

                // TODO - Work on event selection
                if event.action() == Some(OsStr::new("add"))
                    && event.device().property_value(OsStr::new("DEVTYPE"))
                            == Some(OsStr::new("partition")) {
                    // Fetch information from the device
                    let (mut device, signature) = match extract_usb_info(event) {
                        Ok((d,s)) => (d,s),
                        Err(e) => {
                            println!("Error while parsing event: {e}");
                            continue;
                        }
                    };

                    println!("Usb device: {:?}", device);

                    match ctrl_hdl.lock().unwrap().authorize_usb(&device, signature.as_deref()) {
                        Ok(true) => {
                            println!("USB device authorized");
                        },
                        Ok(false) => {
                            println!("USB device blocked");
                        },
                        Err(e) => {
                            println!("Failed to verify USB device: {e}");
                            continue;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Update a usb policy
    ///
    /// # Arguments
    ///
    /// `update` - Information on the usb key and the new authorization status
    fn update_usb_auth(&self, update: &UsbDevice) -> Result<(), anyhow::Error> {
        todo!()
    }

    /// Stop the monitor
    fn stop(self: Box<Self>) {
        todo!()
    }
}