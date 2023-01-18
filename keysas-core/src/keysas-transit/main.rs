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
//#![warn(unstable_features)]
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
use nix::sys::stat;
use serde_derive::Deserialize;
use std::fs::File;
use std::io::IoSliceMut;
use std::os::unix::io::FromRawFd;
use std::os::unix::net::{AncillaryData, SocketAncillary, UnixStream};
use std::path::PathBuf;
use std::str;
use std::thread as main_thread;
use std::time::Duration;
//use utils::sha256_digest;

#[derive(Deserialize, Debug)]
struct Message {
    filename: String,
    digest: String,
}

fn main() -> Result<()> {
    let matches = Command::new("keysas-out")
        .version(crate_version!())
        .author("Stephane N.")
        .about("keysas-in, input window.")
        .arg(
            arg!( -g --sasout <PATH> "Sets Keysas's path for incoming files")
                .default_value("/var/local/out/"),
        )
        .arg(
            arg!( -k --socket <PATH> "Sets a custom socket path").default_value("/run/keysas/sock_in"),
        )
        .get_matches();

    //Won't panic according to clap authors
    let keysasout = matches.get_one::<String>("sasout").unwrap();
    let socket_path = matches.get_one::<String>("socket").unwrap();
    //let sock = UnixStream::connect(socket_path)?;

    //let mut fds = [0; 8];
    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);

    let mut buf = [0; 4096];
    let bufs = &mut [IoSliceMut::new(&mut buf[..])][..];
    //sock.recv_vectored_with_ancillary(bufs, &mut ancillary)?;
    loop {
        let sock = UnixStream::connect(socket_path)?;

        sock.recv_vectored_with_ancillary(bufs, &mut ancillary)?;

        for ancillary_result in ancillary.messages() {
            let data: Message = bincode::deserialize_from(&*bufs[0])?;
            println!("{:?}", data);
            if let AncillaryData::ScmRights(scm_rights) = ancillary_result.unwrap() {
                for fd in scm_rights {
                    //println!("receive file name: {:?}", scm_rights.);
                    println!("Receive file descriptor number: {fd}");
                    let f = unsafe { File::from_raw_fd(fd) };
                    // Open the destination file for writing
                    let mut fileout = PathBuf::new();
                    fileout.push(keysasout);
                    fileout.push(&data.filename);
                    //create the file into keysasout path
                    let _file = File::create(&fileout)?;
                    // Open the destination file for writing
                    let dst_fd = nix::fcntl::open(
                        &fileout,
                        nix::fcntl::OFlag::O_WRONLY,
                        stat::Mode::empty(),
                    )?;

                    // Copy the contents of the source file to the dedicated named pipe
                    let mut buf = [0; 4096];
                    loop {
                        let n = nix::unistd::read(fd, &mut buf)?;
                        if n == 0 {
                            break;
                        }
                        nix::unistd::write(dst_fd, &buf[..n])?;
                    }
                    nix::unistd::close(dst_fd)?;
                    drop(f);

                    println!("Filename is : {}", data.filename);
                    println!("SHA256 is : {}", data.digest);
                }
            }
        }
        main_thread::sleep(Duration::from_millis(500));
    }
}
