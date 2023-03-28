// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-sign".
 *
 * (C) Copyright 2019-2023 Stephane Neveu
 *
 * The code for keysas-sign binary.
 */

pub use anyhow::{anyhow, Context, Result};
use clap::{crate_version, Arg, ArgAction, Command};
use openssl::x509::X509;
use oqs::sig::PublicKey;
use oqs::sig::SecretKey;
use oqs::sig::Sig;
use pkcs8::pkcs5::pbes2;
use pkcs8::LineEnding;
use pkcs8::ObjectIdentifier;
use pkcs8::PrivateKeyInfo;
use std::fs::File;
use std::io::prelude::*;
mod errors;
use std::str;
// Downgrade for ed25519-dalek
use ed25519_dalek::Keypair;
use hex_literal::hex;
use oqs::sig::Algorithm;
use rand_dl::rngs::OsRng;

const FILE_PRIV_PATH: &str = "/etc/keysas/file-sign-priv.pem";
const FILE_CERT_PATH: &str = "/etc/keysas/file-sign-cert.pem";
const FILE_PRIV_PQ_PATH: &str = "/etc/keysas/file-sign-pq-priv.pem";
const FILE_CERT_PQ_PATH: &str = "/etc/keysas/file-sign-pq-cert.pem";
const USB_CERT_PATH: &str = "/etc/keysas/usb-ca-cert.pem";

/// Store command arguments
struct Config {
    generate: bool,    // True for the generate command
    load: bool,        // True for the load command
    name: String,      // Organisation name to put in the certificate request
    cert_type: String, // Certificate type being loaded
    cert: String,      // Certificate value
}

enum KeyType {
    CLASSIC,
    PQ,
}

/// Parse command arguments
/// The tool does only two function:
///   - Generate a new file signing key
///   - Load certificate for the USB CA or its own file signing certificate
fn command_args() -> Config {
    // Start clap CLI definition
    let matches = Command::new("keysas-sign")
    .version(crate_version!())
    .author("Stephane N")
    .about("Keysas tool to manage the station signature certificates")
    .arg(
        Arg::new("generate")
            .short('g')
            .long("generate")
            .value_name("true/false")
            .help("Generate a private for signing purpose (Default is false).")
            .default_value("false")
            .action(ArgAction::SetTrue)
            //.requires("orgname")
            //.requires("orgunit")
            //.requires("country")
            .conflicts_with("load")
    )
    .arg(
        Arg::new("load")
            .short('l')
            .long("load")
            .value_name("true/false")
            .help("Load a certificate on the station of type cert_type.")
            .default_value("false")
            .action(ArgAction::SetTrue)
            .requires("certtype")
            .conflicts_with("generate")
    )
    .arg(
        Arg::new("name")
            .short('n')
            .long("name")
            .value_name("name")
            .help("Name for the station certificate")
            .default_value("")
            .action(clap::ArgAction::Set)
    )
    .arg(
        Arg::new("certtype")
            .short('t')
            .long("certtype")
            .value_name("certtype")
            .help("[file|usb]: file is the station file signature certificate, usb is the CA certificate")
            .default_value("")
            .action(clap::ArgAction::Set)
    )
    .arg(
        Arg::new("cert")
            .short('c')
            .long("cert")
            .value_name("cert")
            .help("Content of the certificate in PEM format")
            .default_value("")
            .action(clap::ArgAction::Set)
    )
    .get_matches();

    Config {
        generate: matches.get_flag("generate"),
        load: matches.get_flag("load"),
        name: matches.get_one::<String>("name").unwrap().to_string(),
        cert_type: matches.get_one::<String>("certtype").unwrap().to_string(),
        cert: matches.get_one::<String>("cert").unwrap().to_string(),
    }
}

/// Store a keypair in a PKCS8 file without password
fn store_keypair(prk: &[u8], pbk: &[u8], kind: KeyType, path: &String) -> Result<()> {
    let params = match pbes2::Parameters::pbkdf2_sha256_aes256cbc(
        2048,
        &hex!("79d982e70df91a88"),
        &hex!("b2d02d78b2efd9dff694cf8e0af40925"),
    ) {
        Ok(p) => p,
        Err(e) => {
            return Err(anyhow!("Failed to generate pkcs5 parameters: {e}"));
        }
    };
    let (label, oid) = match kind {
        KeyType::CLASSIC => ("ED25519", ObjectIdentifier::new("1.3.101.112").unwrap()),
        KeyType::PQ => (
            "Dilithium5",
            ObjectIdentifier::new("1.3.6.1.4.1.2.267.3").unwrap(),
        ),
    };
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
        "(If it failed, you can format manually the newly created partition. Run 'mkfs.vfat {device}1')"
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

    let pk_info = PrivateKeyInfo {
        algorithm: pkcs8::AlgorithmIdentifierRef {
            oid,
            parameters: None,
        },
        private_key: prk,
        public_key: Some(pbk),
    };
    // Caution here: Storing into pkcs8 format using an clear password to be able to write_pem_file
    let pk_encrypted = pk_info.encrypt_with_params(params, "Keysas007").unwrap();
    pk_encrypted.write_pem_file(path, label, LineEnding::LF)?;

    Ok(())
}

fn gen_ed25519() -> Result<Keypair> {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    store_keypair(
        &keypair.secret.to_bytes(),
        &keypair.public.to_bytes(),
        KeyType::CLASSIC,
        &FILE_PRIV_PATH.to_string(),
    )?;
    Ok(keypair)
}

fn gen_pq() -> Result<(PublicKey, SecretKey)> {
    // Create the signing Dilithium L5 keypair
    let pq_scheme = Sig::new(Algorithm::Dilithium5)?;
    let (pk, sk) = pq_scheme.keypair()?;
    store_keypair(
        &sk.as_ref(),
        &pk.as_ref(),
        KeyType::PQ,
        &FILE_PRIV_PQ_PATH.to_string(),
    )?;
    Ok((pk, sk))
}

/// Generate a new key and certification request
/// The private key is saved to a new file at privkey_path
/// The certificate request is a PEM-encoded PKCS#10 structure
fn generate_signing_keypair(config: &Config) -> Result<()> {
    // Generate the private keys
    let _ec_key = gen_ed25519()?;
    let _pq_key = gen_pq()?;
    // Build the csr now

    Ok(())
}

fn save_certificate(cert_type: &String, cert: &String) -> Result<()> {
    if cert_type.eq("usb") {
        // Test if the certificate received is valid
        X509::from_pem(cert.as_bytes())?;
        // Save it to a file
        let mut out = File::create(USB_CERT_PATH)?;
        out.write_all(cert.as_bytes())?;
    } else if cert_type.eq("file") {
        // Test if the certificate received is valid
        X509::from_pem(cert.as_bytes())?;
        // Save it to a file
        let mut out = File::create(FILE_CERT_PATH)?;
        out.write_all(cert.as_bytes())?;
    } else {
        return Err(anyhow!("Invalid certificate type"));
    }
    Ok(())
}

fn main() -> Result<()> {
    let config = command_args();

    // Important load oqs:
    oqs::init();

    if config.generate {
        let req = match generate_signing_keypair(&config) {
            Ok(r) => r,
            Err(e) => {
                return Err(anyhow!("Failed to generate private key {e}"));
            }
        };

        println!("{req:?}");
    } else if config.load {
        match save_certificate(&config.cert_type, &config.cert) {
            Ok(_) => println!("OK"),
            Err(e) => {
                return Err(anyhow!("Failed to generate private key {e}"));
            }
        }
    }
    Ok(())
}
