// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-out".
 *
 * (C) Copyright 2019-2023 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various funtions
 * for building the keysas-out binary.
 */

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
#![feature(unix_socket_ancillary_data)]

use anyhow::Result;
use clap::{arg, crate_version, Command};
use keysas_lib::init_logger;
use serde_derive::Deserialize;
use simple_logger::SimpleLogger;
use std::fs::File;
use std::io::IoSliceMut;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::{AncillaryData, SocketAncillary, UnixStream};
use std::str;
use std::thread as main_thread;
use std::time::Duration;
use std::process;

#[derive(Deserialize, Debug)]
struct Message {
    filename: String,
    digest: String,
}

/// Daemon configuration arguments
struct Configuration {
    path_in: String, // path for the socket with keysas-in
    path_out: String // path for the socket with keysas-out
}

fn parse_args() -> Configuration {
    let matches = Command::new("keysas-out")
        .version(crate_version!())
        .author("Stephane N.")
        .about("keysas-transit, perform file sanitazation.")
        .arg(
            arg!( -i --socket_in <PATH> "Sets a custom socket path for input files").default_value("/run/keysas/sock_in"),
        )
        .arg(
            arg!( -o --socket_out <PATH> "Sets a custom socket path for output files").default_value("/run/keysas/sock_out"),
        )
        .get_matches();

    // Unwrap should not panic with default values
    Configuration {
        path_in: matches.get_one::<String>("socket_in").unwrap().to_string(), 
        path_out: matches.get_one::<String>("socket_out").unwrap().to_string()
    }
}

fn main() -> Result<()> {
    // Parse command arguments
    let config = parse_args();

    // Configure logger
    init_logger();

    // Open socket with keysas-in
    let sock_in = match UnixStream::connect(config.path_in) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open socket with keysas-in");
            process::exit(1);
        }
    };

    // Open socket with keysas-out
    let sock_out = match UnixStream::connect(config.path_out) {
        Ok(s) => s,
        Err(e) => {
            log::error!("Failed to open socket with keysas-out");
            process::exit(1);
        }
    };

    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);

    let mut buf = [0; 4096];
    let bufs = &mut [IoSliceMut::new(&mut buf[..])][..];

    loop {
        sock_in.recv_vectored_with_ancillary(bufs, &mut ancillary)?;

        for ancillary_result in ancillary.messages() {
            let data: Message = bincode::deserialize_from(&*bufs[0])?;
            println!("{:?}", data);
            if let AncillaryData::ScmRights(scm_rights) = ancillary_result.unwrap() {
                for fd in scm_rights {
                    //println!("receive file name: {:?}", scm_rights.);
                    println!("Receive file descriptor number: {fd}");
                    let f = unsafe { File::from_raw_fd(fd) };
                    // Open the destination file for writing
                    //create the file into keysasout path
                    //let _file = File::create(&fileout)?;
                    // Open the destination file for writing
                    //let dst_fd = nix::fcntl::open(
                    //    &fileout,
                    //    nix::fcntl::OFlag::O_WRONLY,
                    //    stat::Mode::empty(),
                    //)?;

                    // Copy the contents of the source file to the dedicated named pipe
                    let mut buf = [0; 4096];
                    loop {
                        let n = nix::unistd::read(fd, &mut buf)?;
                        if n == 0 {
                            break;
                        }
                        //nix::unistd::write(dst_fd, &buf[..n])?;
                    }
                    //nix::unistd::close(dst_fd)?;
                    drop(f);

                    println!("Filename is : {}", data.filename);
                    println!("SHA256 is : {}", data.digest);
                }
            }
        }
        main_thread::sleep(Duration::from_millis(500));
    }
}
