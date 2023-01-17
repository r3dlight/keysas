// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-in".
 *
 * (C) Copyright 2019-2023 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various funtions
 * for building the keysas-in binary.
 */

#![forbid(unsafe_code)]
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
use anyhow::{Context, Result};
use bincode::serialize;
use clap::{arg, crate_version, Command};
use std::fs;
use std::fs::File;
use std::io::IoSlice;
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{SocketAncillary, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread as main_thread;
use std::time::Duration;

#[macro_use]
extern crate serde_derive;
use keysas_lib::{list_files, sha256_digest};

#[derive(Serialize, Debug)]
struct Message {
    filename: String,
    digest: String,
}

fn main() -> Result<()> {
    let matches = Command::new("keysas-in")
        .version(crate_version!())
        .author("Stephane N.")
        .about("keysas-in, input window.")
        .arg(
            arg!( -g --sasin <PATH> "Sets Keysas's path for incoming files")
                .default_value("/var/local/in/"),
        )
        .arg(
            arg!( -k --socket <PATH> "Sets a custom socket path").default_value("/run/keysas/sock"),
        )
        .get_matches();

    //Won't panic according to clap authors
    let keysasin = matches.get_one::<String>("sasin").unwrap();
    let socket_path = matches.get_one::<String>("socket").unwrap();

    if Path::new(socket_path).exists() {
        fs::remove_file(socket_path).expect("Cannot remove socket");
    }

    let sock = UnixListener::bind(socket_path).context("Could not create the unix socket")?;
    //let sock = UnixStream::connect(socket_path)?;
    // put the server logic in a loop to accept several connections
    loop {
        let (unix_stream, _socket_address) = sock
            .accept()
            .context("Failed at accepting a connection on the unix listener")?;
        let files = list_files(keysasin)?;
        for filename in files {
            //spawn a thread here to handle streams

            println!("Passing Fd of file is : {}", filename);
            handle_stream(unix_stream.try_clone()?, keysasin, filename)?;
        }
        main_thread::sleep(Duration::from_millis(500));
    }
    //Ok(())
}

fn handle_stream(stream: UnixStream, keysasin: &String, filename: String) -> Result<()> {
    // to be filled
    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer[..]);
    let mut path_file = PathBuf::new();
    path_file.push(keysasin);
    path_file.push(&filename);
    let digest = sha256_digest(path_file.to_str().unwrap())?;
    let fd = File::open(&path_file)?;
    ancillary.add_fds(&[fd.as_raw_fd()][..]);

    let data = serialize(&Message {
        filename: filename.clone(),
        digest: digest,
    })?;
    let bufs = &mut [IoSlice::new(&data[..])][..];
    //let mut bufs = &mut [IoSlice::new(&buf[..])][..];
    stream.send_vectored_with_ancillary(bufs, &mut ancillary)?;
    println!("Fd closed, removing: {}", path_file.display());
    fs::remove_file(path_file)?;
    Ok(())
}
