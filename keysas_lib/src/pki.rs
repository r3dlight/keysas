// SPDX-License-Identifier: GPL-3.0-only
/*
 * The "keysas-lib".
 *
 * (C) Copyright 2019-2023 Stephane Neveu, Luc Bonnafoux
 *
 * This file contains various funtions
 * for building the keysas_lib.
 */

 #![warn(unused_extern_crates)]
 #![forbid(non_shorthand_field_patterns)]
 #![warn(dead_code)]
 #![warn(missing_debug_implementations)]
 #![warn(missing_copy_implementations)]
 #![warn(trivial_casts)]
 #![warn(trivial_numeric_casts)]
 #![warn(unused_extern_crates)]
 #![warn(unused_import_braces)]
 #![warn(unused_qualifications)]
 #![warn(variant_size_differences)]
 #![forbid(private_in_public)]
 #![warn(overflowing_literals)]
 #![warn(deprecated)]
 #![warn(unused_imports)]

use anyhow::{anyhow, Context};
use ed25519_dalek::Digest;
use ed25519_dalek::Keypair;
use ed25519_dalek::Sha512;
use oqs::sig::Algorithm;
use oqs::sig::SecretKey;
use oqs::sig::Sig;
use pkcs8::der::asn1::OctetString;
use pkcs8::der::asn1::SetOfVec;
use pkcs8::der::oid::db::rfc5280;
use pkcs8::pkcs5::pbes2;
use pkcs8::EncryptedPrivateKeyInfo;
use pkcs8::LineEnding;
use pkcs8::PrivateKeyInfo;
use rand_dl::RngCore;
use rand_dl::rngs::OsRng;
use x509_cert::ext::Extension;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;
use x509_cert::certificate::*;
use x509_cert::der::asn1::BitString;
use x509_cert::der::Encode;
use x509_cert::der::EncodePem;
use x509_cert::name::RdnSequence;
use x509_cert::request::CertReq;
use x509_cert::request::CertReqInfo;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifier;
use x509_cert::spki::ObjectIdentifier;
use x509_cert::spki::SubjectPublicKeyInfo;
use x509_cert::time::Validity;

// Profil des certificats
//
// Root CA profil
//  - Version: "2"
//  - Serial Number: "1"
//  - Signature
//  - Issuer => contains: countryName, organizationName, organizationalUnitName
//  - Validity
//  - Subject
//  - Subject Public key info
//  - [Unique Identifiers: Not used]
//  - Extensions
//      - Authority Key identifiers => Not critical, equals "Subject Key Identifiers"
//      - Subject Key identifiers   =>
//      - Basic constraints         => Critical, cA=True and pathLenConstraint=0
//      - Key usage                 => Critical, keyCertSign
//      - Certificate policies      => Not critical
//
// Station CA profil
//  - Version: "2"
//  - Serial Number: random
//  - Signature
//  - Issuer => contains: countryName, organizationName, organizationalUnitName
//  - Validity
//  - Subject
//  - Subject Public key info
//  - [Unique Identifiers: Not used]
//  - Extensions
//      - Authority Key identifiers => Not critical, equals "Subject Key Identifiers"
//      - Subject Key identifiers   =>
//      - Basic constraints         => Critical, cA=False and pathLenConstraint=1
//      - Key usage                 => Critical, keyCertSign
//      - Certificate policies      => Not critical
//
// Station file signing profil
//  - Version: "2"
//  - Serial Number: random
//  - Signature
//  - Issuer => contains: countryName, organizationName, organizationalUnitName
//  - Validity
//  - Subject
//  - Subject Public key info
//  - [Unique Identifiers: Not used]
//  - Extensions
//      - Authority Key identifiers => Not critical, equals "Subject Key Identifiers"
//      - Subject Key identifiers   =>
//      - Basic constraints         => Critical, cA=False and pathLenConstraint=1
//      - Key usage                 => Critical, digitalSignature
//      - Certificate policies      => Not critical
//
// USB signing profil
//  - Version: "2"
//  - Serial Number: random
//  - Signature
//  - Issuer => contains: countryName, organizationName, organizationalUnitName
//  - Validity
//  - Subject
//  - Subject Public key info
//  - [Unique Identifiers: Not used]
//  - Extensions
//      - Authority Key identifiers => Not critical, equals "Subject Key Identifiers"
//      - Subject Key identifiers   =>
//      - Basic constraints         => Critical, cA=False and pathLenConstraint=1
//      - Key usage                 => Critical, digitalSignature
//      - Certificate policies      => Not critical
//

/// Structure containing informations to build the certificate
#[derive(Debug, Clone)]
pub struct CertificateFields {
    pub org_name:    Option<String>,
    pub org_unit:    Option<String>,
    pub country:     Option<String>,
    pub common_name: Option<String>,
    pub validity:    Option<u32>,
}

#[derive(Debug)]
pub struct KeysasPQKey {
    pub private_key: SecretKey,
    pub public_key: oqs::sig::PublicKey,
}

#[derive(Debug)]
pub struct HybridKeyPair {
    classic: Keypair,
    classic_cert: Certificate,
    pq: KeysasPQKey,
    pq_cert: Certificate,
}

const DILITHIUM5_OID: &str = "1.3.6.1.4.1.2.267.7.8.7";
const ED25519_OID: &str = "1.3.101.112";

impl CertificateFields {
    /// Validate user input and construct a certificate fields structure that can be used
    /// to build the certificates of the PKI.
    /// The checks done are :
    ///     - Test if country is 2 letters long, if less return error, if more shorten it to the first two letters
    ///     - Test if validity can be converted to u32, if not generate error
    ///     - Test if sigAlgo is either ed25519 or ed448, if not defaut to ed25519
    pub fn from_fields<'a>(
        org_name: Option<&'a str>,
        org_unit: Option<&'a str>,
        country: Option<&'a str>,
        common_name: Option<&'a str>,
        validity: Option<&'a str>,
    ) -> Result<CertificateFields, anyhow::Error> {
        // Test if country is 2 letters long
        let cn = country.map(|name| 
            match name.len() {
                0|1 => return Err(anyhow!("Invalid country name")),
                2 => Ok(name.to_string()),
                _ => Ok(name[..2].to_string())
            }
        ).transpose()?;

        // Test if validity can be converted to u32
        let val = validity.map(|value| value.parse::<u32>())
            .transpose()?;

        Ok(CertificateFields {
            org_name: org_name.map(|name| name.to_string()),
            org_unit:org_unit.map(|name| name.to_string()),
            country: cn,
            common_name: common_name.map(|name| name.to_string()),
            validity: val,
        })
    }

    /// Generate a distinghuished name from the input fields for the certificate
    pub fn generate_dn(&self) -> Result<RdnSequence, anyhow::Error> {
        let mut name = String::new();

        // Add country name
        if let Some(cn) = &self.country {
            name.push_str("C=");
            name.push_str(&cn);
            name.push_str(",");
        }

        // Add organisation name
        if let Some(oa) = &self.org_name {
            if name.chars().nth_back(0).is_some_and(|c| !c.eq(&',')) {
                name.push_str(",");
            }
            name.push_str("O=");
            name.push_str(&oa);
            name.push_str(",");
        }

        // Add organisational unit
        if let Some(ou) = &self.org_unit {
            if name.chars().nth_back(0).is_some_and(|c| !c.eq(&',')) {
                name.push_str(",");
            }
            name.push_str("OU=");
            name.push_str(&ou);
            name.push_str(",");
        }

        // Add common name
        if let Some(co) = &self.common_name {
            if name.chars().nth_back(0).is_some_and(|c| !c.eq(&',')) {
                name.push_str(",");
            }
            name.push_str("CN=");
            name.push_str(&co);
            name.push_str(",");
        }

        // Remove trailing ',' if there is one
        if name.chars().nth_back(0).is_some_and(|c| !c.eq(&',')) {
            name.pop();
        }

        let rdn = RdnSequence::from_str(&name)?;
        Ok(rdn)
    }
}

fn create_dir_if_not_exist(path: &String) -> Result<(), anyhow::Error> {
    if !Path::new(path).is_dir() {
        fs::create_dir(path)?;
    }
    Ok(())
}

/// Create the PKI directory hierachy as follows
/// pki_dir
/// |-- CA
/// |   |--root
/// |   |--st
/// |   |--usb
/// |--CRL
/// |--CERT
pub fn create_pki_dir(pki_dir: &String) -> Result<(), anyhow::Error> {
    // Test if the directory path is valid
    if !Path::new(&pki_dir.trim()).is_dir() {
        return Err(anyhow!("Invalid PKI directory path"));
    }

    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CA"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CA/root"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CA/st"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CA/usb"))?;

    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CRL"))?;
    create_dir_if_not_exist(&(pki_dir.to_owned() + "/CERT"))?;

    Ok(())
}

/// Construct a information field for a certificate
fn construct_tbs_certificate(
    issuer_infos: &CertificateFields,
    subject_name: &RdnSequence,
    pub_value: &[u8],
    serial: &[u8],
    algo_oid: &ObjectIdentifier,
    is_app_cert: bool,
    ) -> Result<TbsCertificate, anyhow::Error> {
    // Convert input validity from days to seconds
    let dur = match issuer_infos.validity {
        Some(value) => Duration::new((value * 60 * 60 * 24).into(), 0),
        None => {return Err(anyhow!("Invalid validity value"));}
    };

    // Create Distinguished Names for issuer and subject
    let issuer_name = issuer_infos.generate_dn()?;

    // Convert the public key value to a bit string
    let pub_key =
        BitString::from_bytes(pub_value).with_context(|| "Failed get public key raw value")?;

    // Generate the public key information field
    let pub_key_info = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            oid: *algo_oid,
            parameters: None,
        },
        subject_public_key: pub_key,
    };

    // Create certificate extensions
    let mut extensions: Vec<Extension> = Vec::new();

    // Authority Key Identifier
    // According to RGS, this extension must be present and set to non critical
    // for application certificate
    if is_app_cert {
        extensions.push(Extension {
            extn_id: rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
            critical: false,
            extn_value: OctetString::new(issuer_name.to_der()?)?
        });
    }

    // Key usage
    // According to RGS, must be set to critical
    // Bit 0 is set to indicate digitalSignature
    let ku_value: [u8; 2] = [1, 0];
    extensions.push(Extension {
        extn_id: rfc5280::ID_CE_KEY_USAGE,
        critical: true,
        extn_value: OctetString::new(ku_value.to_vec())?
    });

    // Generate the TBS Certificate structure
    // According to RGS:
    //  - Version is set to V3
    //  - Issuer and subject are set with distinguished names
    //  - Unique Identifiers are not used
    //  - Extensions are set 
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(serial)
            .with_context(|| "Failed to generate serial number")?,
        signature: AlgorithmIdentifier {
            oid: *algo_oid,
            parameters: None,
        },
        issuer: issuer_name,
        validity: Validity::from_now(dur).with_context(|| "Failed to generate validity date")?,
        subject: subject_name.clone(),
        subject_public_key_info: pub_key_info,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: Some(extensions),
    };
    Ok(tbs)
}

/// Generate the root certificate of the PKI from a private key and information
/// fields
/// The function returns the certificate or an openssl error
pub fn generate_root_ed25519(
    infos: &CertificateFields,
) -> Result<(Keypair, Certificate), anyhow::Error> {
    // Create the root CA Ed25519 key pair
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    let ed25519_oid =
        ObjectIdentifier::new(ED25519_OID).with_context(|| "Failed to generate OID")?;

    // Root ED25519 certificate as serial number 1
    let serial: [u8; 1] = [1];

    // Build subject DN
    let subject = infos.generate_dn()?;

    let tbs = construct_tbs_certificate(
        infos,
        &subject,
        &keypair.public.to_bytes(),
        &serial,
        &ed25519_oid,
        true)?;

    let content = tbs.to_der().with_context(|| "Failed to convert to DER")?;
    let mut prehashed = Sha512::new();
    prehashed.update(content);
    let sig = keypair
        .sign_prehashed(prehashed, None)
        .with_context(|| "Failed to sign certificate content")?;

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: AlgorithmIdentifier {
            oid: ed25519_oid,
            parameters: None,
        },
        signature: BitString::from_bytes(&sig.to_bytes())
            .with_context(|| "Failed to convert signature to bytes")?,
    };

    Ok((keypair, cert))
}

pub fn generate_root_dilithium(
    infos: &CertificateFields,
) -> Result<(SecretKey, oqs::sig::PublicKey, Certificate), anyhow::Error> {
    // Create the root CA Dilithium key pair
    let pq_scheme = Sig::new(Algorithm::Dilithium5)?;
    let (pk, sk) = pq_scheme.keypair()?;

    // OID value for dilithium-sha512 from IBM's networking OID range
    let dilithium5_oid = ObjectIdentifier::new(DILITHIUM5_OID)?;

    // Root Dilithium5 certificate as serial number 2
    let serial: [u8; 1] = [2];

    // Build subject DN
    let subject = infos.generate_dn()?;

    let tbs = construct_tbs_certificate(
        infos,
        &subject,
        &pk.clone().into_vec(),
        &serial,
        &dilithium5_oid,
        true)?;

    let content = tbs.to_der()?;

    let signature = pq_scheme.sign(&content, &sk)?;

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: AlgorithmIdentifier {
            oid: dilithium5_oid,
            parameters: None,
        },
        signature: BitString::from_bytes(&signature.into_vec())?,
    };

    Ok((sk, pk, cert))
}

/// Generate PKI root keys
pub fn generate_root(
    infos: &CertificateFields,
    pki_dir: &str,
    pwd: &str,
) -> Result<HybridKeyPair, anyhow::Error> {
    // Generate root ED25519 key and certificate
    let (kp_ed, cert_ed) =
        generate_root_ed25519(infos).with_context(|| "ED25519 generation failed")?;

    // Generate root Dilithium key and certificate
    let (sk_dl, pk_dl, cert_dl) =
        generate_root_dilithium(infos).context("Dilithium generation failed")?;

    // Construct hybrid key pair
    let hk = HybridKeyPair {
        classic: kp_ed,
        classic_cert: cert_ed,
        pq: KeysasPQKey {
            private_key: sk_dl,
            public_key: pk_dl
        },
        pq_cert: cert_dl,
    };

    // Save hybrid key pair to disk
    hk.classic.save_keys(
        Path::new(&(pki_dir.to_owned() + "/CA/root-priv-cl.p8")),
        pwd)
        .context("ED25519 storing failed")?;

    hk.pq.save_keys(
        Path::new(&(pki_dir.to_owned() + "/CA/root-priv-pq.p8")),
        pwd)
        .context("Dilithium storing failed")?;

    // Save certificate pair to disk
    let mut out_cl = File::create(pki_dir.to_owned() + "/CA/root-cert-cl.pem")?;
    write!(
        out_cl,
        "{}",
        hk.classic_cert
            .to_pem(LineEnding::LF)
            .context("ED25519 certificate to pem failed")?
    )?;

    let mut out_pq = File::create(pki_dir.to_owned() + "/CA/root-cert-pq.pem")?;
    write!(
        out_pq,
        "{}",
        hk.pq_cert
            .to_pem(LineEnding::LF)
            .context("Dilithium certificate to pem failed")?
    )?;

    Ok(hk)
}

/// Generate a signed hybrid keypair (ED25519 and Dilithium5)
pub fn generate_signed_keypair(
    ca_keys: &HybridKeyPair,
    subject_name: &RdnSequence,
    pki_infos: &CertificateFields,
    is_app_key: bool
) -> Result<HybridKeyPair, anyhow::Error> {
    // Generate ED25519 key and certificate
    // Create the ED25519 keypair
    let mut csprng = OsRng {};
    let kp_ed = Keypair::generate(&mut csprng);
    // Construct a CSR for the ED25519 key
    let csr_ed = kp_ed.generate_csr(subject_name)?;
    // Generate a certificate from the CSR
    let cert_ed = generate_cert_from_csr(ca_keys, &csr_ed, pki_infos, is_app_key)?;

    // Generate Dilithium key and certificate
    // Create the Dilithium key pair
    let pq_scheme = Sig::new(Algorithm::Dilithium5)?;
    let (pk_dl, sk_dl) = pq_scheme.keypair()?;
    let kp_pq = KeysasPQKey {
        private_key: sk_dl,
        public_key: pk_dl
    };
    // Construct a CSR for the Dilithium key
    let csr_dl = kp_pq.generate_csr(subject_name)?;
    // Generate a certificate from the CSR
    let cert_dl = generate_cert_from_csr(ca_keys, &csr_dl, pki_infos, is_app_key)?;

    // Construct hybrid key pair
    Ok(HybridKeyPair {
        classic: kp_ed,
        classic_cert: cert_ed,
        pq: KeysasPQKey {
            private_key: kp_pq.private_key,
            public_key: kp_pq.public_key
        },
        pq_cert: cert_dl,
    })
}

/// Generate a X509 certificate from a CSR and a CA keypair
/// is_app_cert is set to true if it is an application certificate, otherwise it
///  is considered to be a CA certificate
/// The certificate generated will always be for DigitalSignature
fn generate_cert_from_csr(
    ca_keys: &HybridKeyPair,
    csr: &CertReq,
    pki_info: &CertificateFields,
    is_app_cert: bool
) -> Result<Certificate, anyhow::Error> {
    // Extract and validate info in the CSR
    let subject = csr.info.subject.clone();

    let pub_key = csr.info.public_key.subject_public_key
        .as_bytes().ok_or(anyhow!("Subject public key missing"))?;

    let dilithium5_oid = ObjectIdentifier::new(DILITHIUM5_OID)?;
    let ed25519_oid = ObjectIdentifier::new(ED25519_OID)?;

    // Build the certificate
    if let Ok(_) = csr
        .info
        .public_key
        .algorithm
        .assert_algorithm_oid(ed25519_oid)
    {
        // Validate CSR authenticity
        let key = ed25519_dalek::PublicKey::from_bytes(pub_key)?;
        if let Err(_) = key.verify_strict(
            &csr.info.to_der()?, 
            &ed25519_dalek::Signature::from_bytes(csr.signature.raw_bytes())?) {
            return Err(anyhow!("Invalid CSR signature"));
        }

        // Generate serial number
        let mut serial = [0u8; 20];
        OsRng.fill_bytes(&mut serial);

        // Build the certificate
        let cert = ca_keys.classic.generate_certificate(
            pki_info,
            &subject,
            pub_key,
            &serial,
            is_app_cert)?;

        Ok(cert)
    } else if let Ok(_) = csr
        .info
        .public_key
        .algorithm
        .assert_algorithm_oid(dilithium5_oid)
    {
        // Validate CSR authenticity
        oqs::init();
        let pq_scheme = Sig::new(Algorithm::Dilithium5)?;
        if let Err(_) = pq_scheme.verify(
            &csr.info.to_der()?,
            &pq_scheme.signature_from_bytes(csr.signature.raw_bytes())
                .ok_or(anyhow!("Failed to create signature"))?,
            &pq_scheme.public_key_from_bytes(pub_key)
                .ok_or(anyhow!("Failed to create public key"))?
        ) {
            return Err(anyhow!("Invalid CSR signature"));
        }

        // Generate serial number
        let mut serial = [0u8; 20];
        OsRng.fill_bytes(&mut serial);

        // Build the certificate
        let cert = ca_keys.pq.generate_certificate(
            pki_info,
            &subject,
            pub_key,
            &serial,
            is_app_cert)?;

        Ok(cert)
    } else {
        return Err(anyhow!("Invalid algorithm OID"));
    }
}

/// Store a keypair in a PKCS8 file with a password
fn store_keypair(
    prk: &[u8],
    pbk: &[u8],
    oid: ObjectIdentifier,
    pwd: &str,
    path: &Path,
) -> Result<(), anyhow::Error> {
    //Initialize key wrap function parameters
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut iv = [0u8; 16];
    OsRng.fill_bytes(&mut iv);
    // Use default parameters for scrypt
    let params = match pbes2::Parameters::scrypt_aes256cbc(
        pkcs8::pkcs5::scrypt::Params::recommended(),
        &salt,
        &iv,
    ) {
        Ok(p) => p,
        Err(e) => {
            return Err(anyhow!("Failed to generate scrypt parameter: {e}"));
        }
    };

    let pk_info = PrivateKeyInfo {
        algorithm: pkcs8::AlgorithmIdentifierRef {
            oid,
            parameters: None,
        },
        private_key: prk,
        public_key: Some(pbk),
    };

    let pk_encrypted = match pk_info.encrypt_with_params(params, pwd) {
        Ok(pk) => pk,
        Err(e) => {
            log::error!("Failed to encrypt private key: {e}");
            return Err(anyhow!("Failed to encrypt private key"));
        }
    };

    pk_encrypted.write_der_file(path)?;

    Ok(())
}

/// Generic trait to abstract the main functions of the ED25519 and Dilthium keys
pub trait KeysasKey<T> {
    /// Load keypair from a DER encoded PKCS8 file protected with a password
    fn load_keys(path: &Path, pwd: &str) -> Result<T, anyhow::Error>;
    /// Save keypair in a DER encoded PKCS8 file protected with a password
    fn save_keys(&self, path: &Path, pwd: &str) -> Result<(), anyhow::Error>;
    /// Generate a Certificate Signing Request for the keypair and with the subject name
    fn generate_csr(&self, subject: &RdnSequence) -> Result<CertReq, anyhow::Error>;
    /// Sign a message
    fn message_sign(&self, message: &[u8]) -> Result<Vec<u8>, anyhow::Error>;
    /// Verify the signature of a message
    fn message_verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, anyhow::Error>;
    /// Generate a certificate from a CSR and signed with the key
    fn generate_certificate(&self,
        ca_infos: &CertificateFields, 
        subject_infos: &RdnSequence,
        subject_key: &[u8],
        serial: &[u8],
        is_app_cert: bool) -> Result<Certificate, anyhow::Error>;
}

// Implementing new methods on top of dalek Keypair
impl KeysasKey<Keypair> for Keypair {
    fn load_keys(path: &Path, pwd: &str) -> Result<Keypair, anyhow::Error> {
        // Load the pkcs8 from file
        let cipher = fs::read(path)?;

        let enc_pk = match EncryptedPrivateKeyInfo::try_from(cipher.as_slice()) {
            Ok(ep) => ep,
            Err(e) => {
                return Err(anyhow!("Failed to parse EncryptedPrivateKeyInfo: {e}"));
            }
        };
        let pk = match enc_pk.decrypt(pwd) {
            Ok(p) => p,
            Err(e) => {
                return Err(anyhow!("Failed to decrypt document: {e}"));
            }
        };
        let decoded_pk: PrivateKeyInfo = match pk.decode_msg() {
            Ok(parsed_pk) => parsed_pk,
            Err(e) => {
                return Err(anyhow!(
                    "Failed to decode asn.1 format for private key: {e}"
                ));
            }
        };
        // ed25519 is only 32 bytes long
        if decoded_pk.private_key.len() == 32 {
            match ed25519_dalek::SecretKey::from_bytes(decoded_pk.private_key) {
                Ok(secret_key) => {
                    return Ok(Keypair {
                        public: (&(secret_key)).into(),
                        secret: secret_key,
                    });
                }
                Err(e) => {
                    return Err(anyhow!(
                        "Cannot parse private key CLASSIC/ed25519-dalek from pkcs#8: {e}"
                    ));
                }
            };
        } else {
            return Err(anyhow!("Key is not 32 bytes long"));
        }
    }

    fn save_keys(&self, path: &Path, pwd: &str) -> Result<(), anyhow::Error> {
        let ed25519_oid = ObjectIdentifier::new(ED25519_OID)?;

        store_keypair(
            self.secret.as_bytes(),
            self.public.as_bytes(), 
            ed25519_oid,
            pwd,
            path
        )
    }

    fn generate_csr(&self, subject: &RdnSequence) -> Result<CertReq, anyhow::Error> {
        let ed25519_oid = ObjectIdentifier::new(ED25519_OID)?;

        let pub_key = BitString::from_bytes(&self.public.to_bytes())
            .with_context(|| "Failed get public key raw value")?;

        let info = CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: subject.to_owned(),
            public_key: SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    oid: ed25519_oid,
                    parameters: None,
                },
                subject_public_key: pub_key,
            },
            attributes: SetOfVec::new(),
        };

        let content = info.to_der().with_context(|| "Failed to convert to DER")?;
        let mut prehashed = Sha512::new();
        prehashed.update(content);
        let signature = self
            .sign_prehashed(prehashed, None)
            .with_context(|| "Failed to sign certificate content")?;

        let csr = CertReq {
            info,
            algorithm: AlgorithmIdentifier {
                oid: ed25519_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature.to_bytes())?,
        };

        Ok(csr)
    }

    fn message_sign(&self, message: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        let mut prehashed = Sha512::new();
        prehashed.update(message);
        let signature = self.sign_prehashed(prehashed, None)?;
        Ok(signature.to_bytes().to_vec())
    }

    fn message_verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, anyhow::Error> {
        let sig = ed25519_dalek::Signature::from_bytes(signature)?;
        self.verify(message, &sig)?;
        // If no error has been returned then the signature is valid
        Ok(true)
    }

    fn generate_certificate(&self,
        ca_infos: &CertificateFields, 
        subject_infos: &RdnSequence,
        subject_key: &[u8],
        serial: &[u8],
        is_app_cert: bool) -> Result<Certificate, anyhow::Error> {
        
        let ed25519_oid = ObjectIdentifier::new(ED25519_OID)?;

        // Build the certificate
        let tbs = construct_tbs_certificate(
            ca_infos,
            subject_infos,
            subject_key,
            serial,
            &ed25519_oid,
            is_app_cert)?;

        let content = tbs.to_der().with_context(|| "Failed to convert to DER")?;
        let mut prehashed = Sha512::new();
        prehashed.update(content);
        let signature = self.sign_prehashed(prehashed, None)
            .with_context(|| "Failed to sign certificate content")?;

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: AlgorithmIdentifier {
                oid: ed25519_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature.to_bytes())?,
        };
        Ok(cert)
    }
}

impl KeysasKey<KeysasPQKey> for KeysasPQKey {
    fn load_keys(path: &Path, pwd: &str) -> Result<KeysasPQKey, anyhow::Error> {
        // Load the pkcs8 from file
        let cipher = fs::read(path)?;
        let enc_pk = match EncryptedPrivateKeyInfo::try_from(cipher.as_slice()) {
            Ok(ep) => ep,
            Err(e) => {
                return Err(anyhow!("Failed to parse EncryptedPrivateKeyInfo: {e}"));
            }
        };
        let pk = match enc_pk.decrypt(pwd) {
            Ok(p) => p,
            Err(e) => {
                return Err(anyhow!("Failed to decrypt document: {e}"));
            }
        };
        let decoded_pk: PrivateKeyInfo = match pk.decode_msg() {
            Ok(parsed_pk) => parsed_pk,
            Err(e) => {
                return Err(anyhow!(
                    "Failed to decode asn.1 format for private key: {e}"
                ));
            }
        };
        oqs::init();
        let scheme = match oqs::sig::Sig::new(oqs::sig::Algorithm::Dilithium5) {
            Ok(scheme) => scheme,
            Err(e) => {
                return Err(anyhow!(
                    "OQS error: cannot initialize Dililthium5 scheme: {e}"
                ))
            }
        };
        let tmp_pq_sk = match oqs::sig::Sig::secret_key_from_bytes(&scheme, decoded_pk.private_key)
        {
            Some(tmp_sig_sk) => tmp_sig_sk,
            None => {
                return Err(anyhow!(
                    "Cannot parse secret pq private key from decode value"
                ));
            }
        };
        let secret_key = tmp_pq_sk.to_owned();
        match decoded_pk.public_key {
            Some(public_key_u8) => {
                let public_key = match oqs::sig::Sig::public_key_from_bytes(&scheme, public_key_u8)
                {
                    Some(p) => p,
                    None => {
                        return Err(anyhow!("Cannot parse PQC public key from pkcs#8"));
                    }
                };
                return Ok(KeysasPQKey {
                    private_key: secret_key,
                    public_key: public_key.to_owned(),
                });
            }
            None => {
                return Err(anyhow!("No PQC public key found in pkcs#8 format"));
            },
        };
    }

    fn save_keys(&self, path: &Path, pwd: &str) -> Result<(), anyhow::Error> {
        let ed25519_oid = ObjectIdentifier::new(ED25519_OID)?;

        store_keypair(
            &self.private_key.clone().into_vec(),
            &self.public_key.clone().into_vec(), 
            ed25519_oid,
            pwd,
            path
        )
    }

    fn generate_csr(&self, subject: &RdnSequence) -> Result<CertReq, anyhow::Error> {
        let dilithium5_oid = ObjectIdentifier::new(DILITHIUM5_OID)?;

        let pub_key = BitString::from_bytes(&self.public_key.clone().into_vec())
            .with_context(|| "Failed get public key raw value")?;
    
        let info = CertReqInfo {
            version: x509_cert::request::Version::V1,
            subject: subject.to_owned(),
            public_key: SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier {
                    oid: dilithium5_oid,
                    parameters: None,
                },
                subject_public_key: pub_key,
            },
            attributes: SetOfVec::new(),
        };
    
        let content = info.to_der().with_context(|| "Failed to convert to DER")?;
        let pq_scheme = Sig::new(Algorithm::Dilithium5)?;
        let signature = pq_scheme.sign(&content, &self.private_key)?;
    
        let csr = CertReq {
            info,
            algorithm: AlgorithmIdentifier {
                oid: dilithium5_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature.into_vec())?,
        };
    
        Ok(csr)
    }

    fn message_sign(&self, message: &[u8]) -> Result<Vec<u8>, anyhow::Error> {
        oqs::init();
        let pq_scheme = Sig::new(Algorithm::Dilithium5)?;
        let signature = pq_scheme.sign(message, &self.private_key)?;
        Ok(signature.into_vec())
    }

    fn message_verify(&self, message: &[u8], signature: &[u8]) -> Result<bool, anyhow::Error> {
        oqs::init();
        let pq_scheme = Sig::new(Algorithm::Dilithium5)?;
        let sig = match pq_scheme.signature_from_bytes(signature) {
            Some(s) => s,
            None => {
                return Err(anyhow!("Invalid signature input"));
            }
        };
        pq_scheme.verify(
            message,
            sig,
            &self.public_key)?;
        // If no error then the signature is valid
        Ok(true)
    }

    fn generate_certificate(&self,
        ca_infos: &CertificateFields, 
        subject_infos: &RdnSequence,
        subject_key: &[u8],
        serial: &[u8],
        is_app_cert: bool) -> Result<Certificate, anyhow::Error> {
        
        let dilithium5_oid = ObjectIdentifier::new(DILITHIUM5_OID)?;

        // Build the certificate
        let tbs = construct_tbs_certificate(
            ca_infos,
            subject_infos,
            subject_key,
            serial,
            &dilithium5_oid,
            is_app_cert)?;

        let content = tbs.to_der().with_context(|| "Failed to convert to DER")?;
        
        let pq_scheme = Sig::new(Algorithm::Dilithium5)?;
        let signature = pq_scheme.sign(&content, &self.private_key)?;

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: AlgorithmIdentifier {
                oid: dilithium5_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature.into_vec())?,
        };
        Ok(cert)
    }
}
