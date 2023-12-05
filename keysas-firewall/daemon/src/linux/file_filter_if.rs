// SPDX-License-Identifier: GPL-3.0-only
/*
 *
 * (C) Copyright 2019-2023 Luc Bonnafoux, Stephane Neveu
 *
 */

//! FileFilterInterface is a generic interface to send and receive messages
//! to the file filter in kernel space.
//! The interface must be specialized for Linux or Windows

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

use aya::{include_bytes_aligned, programs::lsm::Lsm, BpfLoader, Btf};
use aya_log::BpfLogger;
use log::*;
use std::{
    boxed::Box,
    fs::create_dir_all,
    path::Path,
    sync::{Arc, Mutex},
    thread,
};
use tokio::runtime::Runtime;

use crate::controller::{FilteredFile, ServiceController};
use crate::file_filter_if::FileFilterInterface;

#[derive(Debug, Copy, Clone)]
pub struct LinuxFileFilterInterface {}

impl LinuxFileFilterInterface {
    /// Initialize the kernel filter interface
    pub fn init() -> Result<LinuxFileFilterInterface, anyhow::Error> {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        Ok(LinuxFileFilterInterface {})
    }
}

async fn start_bpf() -> Result<(), anyhow::Error> {
    let lsm_base_path = Path::new("/sys/fs/bpf/keysas");
    create_dir_all(&lsm_base_path)?;

    #[cfg(debug_assertions)]
    let mut bpf = BpfLoader::new()
        .map_pin_path(lsm_base_path)
        .load(include_bytes_aligned!(
            "../../../ebpfilter/target/bpfel-unknown-none/debug/lsm-file"
        ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = BpfLoader::new()
        .map_pin_path(lsm_base_path)
        .load(include_bytes_aligned!(
            "../../../ebpfilter/target/bpfel-unknown-none/release/lsm-file"
        ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let lsm: &mut Lsm = bpf.program_mut("file_open").unwrap().try_into()?;
    let btf = Btf::from_sys_fs()?;
    lsm.load("file_open", &btf)?;
    lsm.attach()?;

    loop {}
}

impl FileFilterInterface for LinuxFileFilterInterface {
    /// Start listening for request on the interface
    ///
    /// # Arguments
    ///
    /// `ctrl` - Handle to the service controller
    fn start(&self, ctrl: &Arc<Mutex<ServiceController>>) -> Result<(), anyhow::Error> {
        // Create a tokio runtime to handle BPF program loading and events
        // Run it in its own thread
        let res = thread::spawn(|| -> Result<(), anyhow::Error> {
            let rt = Runtime::new()?;

            if let Err(e) = rt.block_on(start_bpf()) {
                println!("BPF thread failed with error: {e}");
            }

            println!("Coucou");

            Ok(())
        });

        Ok(())
    }

    /// Update the control policy on a file
    ///
    /// # Arguments
    ///
    /// `update` - Information on the file and the new authorization status
    fn update_file_auth(&self, update: &FilteredFile) -> Result<(), anyhow::Error> {
        todo!()
    }

    /// Stop the interface and free resources
    fn stop(self: Box<Self>) {}
}
