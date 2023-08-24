use anyhow::anyhow;
use keysas_lib::certificate_field::validate_signing_certificate;
use pkcs8::der::EncodePem;
use ssh_rs::LocalSession;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::net::TcpStream;
use std::path::Path;
use x509_cert::der::DecodePem;
use x509_cert::request::CertReq;
use x509_cert::Certificate;

use crate::ssh_wrapper::session_exec;

/// Wrapper function to triger a signing key generation on a station and
/// recover CSRs from it
pub fn cmd_generate_key_and_get_csr(
    session: &mut LocalSession<TcpStream>,
    name: &str,
) -> Result<(CertReq, CertReq), anyhow::Error> {
    let command = format!(
        "{}{}{}",
        "sudo /usr/bin/keysas-sign --generate", " --name ", name
    );
    let cmd_res = match session_exec(session, &command) {
        Ok(res) => res,
        Err(why) => {
            log::error!("Error on send_command: {:?}", why);
            return Err(anyhow!("Connection failed"));
        }
    };

    let cert_req = String::from_utf8(cmd_res)?;
    log::debug!("{cert_req:?}");

    // Recover the CSR from the session command
    let mut csrs = cert_req.split('|');
    let csr_cl = match csrs.next().and_then(|pem| match CertReq::from_pem(pem) {
        Ok(c) => Some(c),
        Err(e) => {
            log::error!("Failed to parse classic certification request (1): {e}");
            None
        }
    }) {
        Some(csr) => csr,
        None => {
            return Err(anyhow!("Failed to parse classic certification request (2)"));
        }
    };

    let csr_pq = match csrs.remainder().and_then(|pem| {
        match CertReq::from_pem(pem.trim_end_matches("\n\n")) {
            Ok(c) => Some(c),
            Err(e) => {
                log::debug!("{pem:?}");
                log::error!("Failed to parse PQC certification request (1): {e}");
                None
            }
        }
    }) {
        Some(csr) => csr,
        None => {
            return Err(anyhow!("Failed to parse PQC certification request (2)"));
        }
    };

    Ok((csr_cl, csr_pq))
}

/// Utility function to load a certificate on the station
/// Kind:
///     - file-cl: certificate for ED25519 station files signing
///     - file-pq: certificate for Dilithium5 station files signing
///     - usb-cl: certificate for ED25519 USB signing
///     - usb-pq: certificate for Dilithium5 USB signing
pub fn send_cert_to_station(
    session: &mut LocalSession<TcpStream>,
    cert: &Certificate,
    kind: &str,
) -> Result<(), anyhow::Error> {
    let output = String::from_utf8(cert.to_pem(pkcs8::LineEnding::LF)?.into())?;

    let command = format!(
        "{}{}{}{}",
        "sudo /usr/bin/keysas-sign --load --certtype ",
        kind,
        " --cert=",
        "\"".to_owned() + &output + "\"",
    );

    if let Err(e) = session_exec(session, &command) {
        log::error!("Failed to load certificate on the station: {e}");
        return Err(anyhow!("Connection error"));
    }

    let command = "sudo /bin/chown keysas-out:keysas-out /etc/keysas/file-sign-cl.p8 /etc/keysas/file-sign-cl.pem /etc/keysas/file-sign-pq.p8 /etc/keysas/file-sign-pq.pem /etc/keysas/usb-ca-cl.pem /etc/keysas/usb-ca-pq.pem".to_string();

    if let Err(e) = session_exec(session, &command) {
        log::error!("Failed to chown files: {e}");
        return Err(anyhow!("Connection error"));
    }

    let command = "sudo /bin/systemctl restart keysas".to_string();

    if let Err(e) = session_exec(session, &command) {
        log::error!("Failed to restart Keysas: {e}");
        return Err(anyhow!("Connection error"));
    }

    Ok(())
}

pub fn save_certificate(cert: &Certificate, path: &Path) -> Result<(), anyhow::Error> {
    let output = String::from_utf8(cert.to_pem(pkcs8::LineEnding::LF)?.into())?;
    let mut file = File::create(path)?;
    write!(file, "{}", output)?;
    Ok(())
}

/// Test if every directories and p8 and pem files are presents
/// into the right path.
/// Returns an error if not
pub fn check_pki_structure(base_directory: &String) -> Result<(), anyhow::Error> {
    let base_directory = Path::new(base_directory);
    // Step 1: Any directories or files bellow must be found
    let directories_and_files = [
        ("root", "root-cl.p8"),
        ("root", "root-cl.pem"),
        ("root", "root-pq.p8"),
        ("root", "root-pq.pem"),
        ("st", "st-ca-cl.p8"),
        ("st", "st-ca-cl.pem"),
        ("st", "st-ca-pq.p8"),
        ("st", "st-ca-pq.pem"),
        ("usb", "usb-cl.p8"),
        ("usb", "usb-cl.pem"),
        ("usb", "usb-pq.p8"),
        ("usb", "usb-pq.pem"),
    ];
    if base_directory.join("CA").is_dir() {
        for (directory, file) in directories_and_files.iter() {
            let subdirectory_path = base_directory.join("CA").join(directory);
            let file_path = subdirectory_path.join(file);

            if subdirectory_path.exists() && subdirectory_path.is_dir() {
                if file_path.exists() && file_path.is_file() {
                    log::debug!("Found file {} in directory {}.", file, directory);
                } else {
                    log::error!("File {} not found in directory {}.", file, directory);
                    return Err(anyhow!("Invalid algorithm OID"));
                }
            } else {
                log::error!("Directory {:?} doesn't exist.", subdirectory_path);
                return Err(anyhow!("Directory do not exist"));
            }
        }
    } else {
        return Err(anyhow!("Directory CA does not exist."));
    }
    // Now let's validate the certificates before importing them into db
    let root_pq_file_content =
        match fs::read_to_string(base_directory.join("CA").join("root").join("root-pq.pem")) {
            Ok(rpp) => rpp,
            Err(why) => return Err(anyhow!("Root Dilithium certificate not found: {why}")),
        };

    let root_pq_pem = match validate_signing_certificate(&root_pq_file_content, None) {
        Ok(rpp) => rpp,
        Err(why) => {
            return Err(anyhow!(
                "Error validating root Dilithium certificate: {:?}",
                why,
            ))
        }
    };
    log::debug!("Root Dilithium certificate validated.");
    let root_cl_file_content =
        match fs::read_to_string(base_directory.join("CA").join("root").join("root-cl.pem")) {
            Ok(rcp) => rcp,
            Err(why) => return Err(anyhow!("Root Ed25519 certificate not found: {why}")),
        };
    let root_cl_pem = match validate_signing_certificate(&root_cl_file_content, None) {
        Ok(rcp) => rcp,
        Err(why) => {
            return Err(anyhow!(
                "Error validating root Ed25519 certificate: {:?}",
                why
            ))
        }
    };
    log::debug!("Root Ed25519 certificate validated.");
    let st_pq_file_content =
        match fs::read_to_string(base_directory.join("CA").join("st").join("st-ca-pq.pem")) {
            Ok(spp) => spp,
            Err(why) => return Err(anyhow!("Station Dilithium certificate not found: {why}")),
        };
    match validate_signing_certificate(&st_pq_file_content, Some(&root_pq_pem)) {
        Ok(_) => log::debug!("Dilithium station certificate signature is valid."),
        Err(why) => {
            return Err(anyhow!(
                "Error validating station Dilithium certificate signature: {:?}",
                why
            ))
        }
    }
    let st_cl_file_content =
        match fs::read_to_string(base_directory.join("CA").join("st").join("st-ca-cl.pem")) {
            Ok(scp) => scp,
            Err(why) => return Err(anyhow!("Station Ed25519 certificate not found: {why}")),
        };
    match validate_signing_certificate(&st_cl_file_content, Some(&root_cl_pem)) {
        Ok(_) => log::debug!("Ed25519 station certificate signature is valid."),
        Err(why) => {
            return Err(anyhow!(
                "Error validating station Ed25519 certificate signature: {:?}",
                why
            ))
        }
    }
    Ok(())
}
