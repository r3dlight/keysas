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
use hex_literal::hex;
use oqs::sig::Algorithm;
use oqs::sig::PublicKey;
use oqs::sig::SecretKey;
use oqs::sig::Sig;
use pkcs8::der::asn1::SetOfVec;
use pkcs8::pkcs5::pbes2;
use pkcs8::pkcs5::scrypt::scrypt;
use pkcs8::DecodePrivateKey;
use pkcs8::EncryptedPrivateKeyInfo;
use pkcs8::LineEnding;
use pkcs8::PrivateKeyInfo;
use rand_dl::rngs::OsRng;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;
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
#[derive(Debug)]
pub struct CertificateFields {
    pub org_name: String,
    pub org_unit: String,
    pub country: String,
    pub validity: u32,
}

#[derive(Debug)]
pub struct HybridKeyPair {
    classic: Keypair,
    classic_cert: Certificate,
    pq_priv: SecretKey,
    pq_pub: PublicKey,
    pq_cert: Certificate,
}
#[derive(Debug)]
pub enum KeyType {
    CLASSIC,
    PQ,
}

#[derive(Debug)]
pub struct KeysasPQKey {
    pub private_key: SecretKey,
    pub public_key: PublicKey,
}

const DILITHIUM5_OID: &str = "1.3.6.1.4.1.2.267.7.8.7";
const ED25519_OID: &str = "1.3.101.112";

/// Validate user input and construct a certificate fields structure that can be used
/// to build the certificates of the PKI.
/// The checks done are :
///     - Test if country is 2 letters long, if less return error, if more shorten it to the first two letters
///     - Test if validity can be converted to u32, if not generate error
///     - Test if sigAlgo is either ed25519 or ed448, if not defaut to ed25519
pub fn validate_input_cert_fields<'a>(
    org_name: &'a String,
    org_unit: &'a String,
    country: &'a String,
    validity: &'a String,
) -> Result<CertificateFields, ()> {
    // Test if country is 2 letters long
    let cn = match country.len() {
        0 | 1 => return Err(()),
        2 => country.to_string(),
        _ => country[..2].to_string(),
    };
    // Test if validity can be converted to u32
    let val = match validity.parse::<u32>() {
        Ok(v) => v,
        Err(_) => return Err(()),
    };

    Ok(CertificateFields {
        org_name: org_name.to_string(),
        org_unit: org_unit.to_string(),
        country: cn,
        validity: val,
    })
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

fn construct_tbs_certificate(
    infos: &CertificateFields,
    pub_value: &[u8],
    algo_oid: &ObjectIdentifier,
) -> Result<TbsCertificate, anyhow::Error> {
    let dur = Duration::new((infos.validity * 60 * 60 * 24).into(), 0);
    let issuer_name = RdnSequence::default();
    let subject_name = RdnSequence::default();
    let pub_key =
        BitString::from_bytes(pub_value).with_context(|| "Failed get public key raw value")?;
    let pub_key_info = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier {
            oid: *algo_oid,
            parameters: None,
        },
        subject_public_key: pub_key,
    };
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[1])
            .with_context(|| "Failed to generate serial number")?,
        signature: AlgorithmIdentifier {
            oid: *algo_oid,
            parameters: None,
        },
        issuer: issuer_name,
        validity: Validity::from_now(dur).with_context(|| "Failed to generate validity date")?,
        subject: subject_name,
        subject_public_key_info: pub_key_info,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
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

    let tbs = match construct_tbs_certificate(infos, &keypair.public.to_bytes(), &ed25519_oid) {
        Ok(tbs) => tbs,
        Err(e) => {
            return Err(anyhow!("Failed to construct TBS certificate: {e}"));
        }
    };

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
) -> Result<(SecretKey, PublicKey, Certificate), anyhow::Error> {
    // Create the root CA Dilithium key pair
    let pq_scheme = Sig::new(Algorithm::Dilithium5)?;
    let (pk, sk) = pq_scheme.keypair()?;

    // OID value for dilithium-sha512 from IBM's networking OID range
    let dilithium5_oid = ObjectIdentifier::new(DILITHIUM5_OID)?;
    let tbs = construct_tbs_certificate(infos, &pk.clone().into_vec(), &dilithium5_oid)?;
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
    pki_dir: &String,
    pwd: &String,
) -> Result<HybridKeyPair, anyhow::Error> {
    // Generate root ED25519 key and certificate
    let (kp_ed, cert_ed) =
        generate_root_ed25519(&infos).with_context(|| "ED25519 generation failed")?;

    // Generate root Dilithium key and certificate
    let (sk_dl, pk_dl, cert_dl) =
        generate_root_dilithium(&infos).context("Dilithium generation failed")?;

    // Construct hybrid key pair
    let hk = HybridKeyPair {
        classic: kp_ed,
        classic_cert: cert_ed,
        pq_priv: sk_dl,
        pq_pub: pk_dl,
        pq_cert: cert_dl,
    };

    // Save hybrid key pair to disk
    store_keypair(
        &hk.classic.secret.to_bytes(),
        &hk.classic.public.to_bytes(),
        KeyType::CLASSIC,
        pwd,
        &(pki_dir.to_owned() + "/CA/root-priv-cl.p8"),
    )
    .context("ED25519 storing failed")?;

    store_keypair(
        hk.pq_priv.as_ref(),
        hk.pq_pub.as_ref(),
        KeyType::PQ,
        pwd,
        &(pki_dir.to_owned() + "/CA/root-priv-pq.p8"),
    )
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

pub fn generate_signed_keypair(
    ca_keys: &HybridKeyPair,
    subject_infos: &CertificateFields,
    pki_infos: &CertificateFields,
) -> Result<HybridKeyPair, anyhow::Error> {
    // Create the subject name for the certificate
    let subject = RdnSequence::default();

    // Generate ED25519 key and certificate
    // Create the ED25519 keypair
    let mut csprng = OsRng {};
    let kp_ed = Keypair::generate(&mut csprng);
    // Construct a CSR for the ED25519 key
    let csr_ed = kp_ed.generate_csr(&subject)?;
    // Generate a certificate from the CSR
    let cert_ed = generate_cert_from_csr(ca_keys, &csr_ed, pki_infos)?;

    // Generate Dilithium key and certificate
    // Create the Dilithium key pair
    let pq_scheme = Sig::new(Algorithm::Dilithium5)?;
    let (pk_dl, sk_dl) = pq_scheme.keypair()?;
    let kp_pq = KeysasPQKey {
        private_key: sk_dl,
        public_key: pk_dl
    };
    // Construct a CSR for the Dilithium key
    let csr_dl = kp_pq.generate_csr(&subject)?;
    // Generate a certificate from the CSR
    let cert_dl = generate_cert_from_csr(ca_keys, &csr_dl, pki_infos)?;

    // Construct hybrid key pair
    Ok(HybridKeyPair {
        classic: kp_ed,
        classic_cert: cert_ed,
        pq_priv: kp_pq.private_key,
        pq_pub: kp_pq.public_key,
        pq_cert: cert_dl,
    })
}

fn generate_cert_from_csr(
    ca_keys: &HybridKeyPair,
    csr: &CertReq,
    pki_info: &CertificateFields,
) -> Result<Certificate, anyhow::Error> {
    // Extract and validate info in the CSR
    //TODO: validate CSR authenticity

    let subject = csr.info.subject.clone();
    //TODO: validate subject

    let pub_key = match csr.info.public_key.subject_public_key.as_bytes() {
        Some(k) => {
            //TODO: validate key
            k
        }
        None => {
            return Err(anyhow!("Invalid public key in CSR"));
        }
    };

    let dilithium5_oid = ObjectIdentifier::new(DILITHIUM5_OID)?;
    let ed25519_oid = ObjectIdentifier::new(ED25519_OID)?;

    // Build the certificate
    if let Ok(oid) = csr
        .info
        .public_key
        .algorithm
        .assert_algorithm_oid(ed25519_oid)
    {
        // Build the certificate
        let tbs = construct_tbs_certificate(pki_info, pub_key, &oid)?;

        let content = tbs.to_der().with_context(|| "Failed to convert to DER")?;
        let mut prehashed = Sha512::new();
        prehashed.update(content);
        let signature = ca_keys
            .classic
            .sign_prehashed(prehashed, None)
            .with_context(|| "Failed to sign certificate content")?;

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: AlgorithmIdentifier {
                oid: dilithium5_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature.to_bytes())?,
        };

        Ok(cert)
    } else if let Ok(oid) = csr
        .info
        .public_key
        .algorithm
        .assert_algorithm_oid(dilithium5_oid)
    {
        let tbs = construct_tbs_certificate(pki_info, pub_key, &oid)?;
        let content = tbs.to_der()?;

        let pq_scheme = Sig::new(Algorithm::Dilithium5)?;
        let signature = pq_scheme.sign(&content, &ca_keys.pq_priv)?;

        let cert = Certificate {
            tbs_certificate: tbs,
            signature_algorithm: AlgorithmIdentifier {
                oid: dilithium5_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature.into_vec())?,
        };

        Ok(cert)
    } else {
        return Err(anyhow!("Invalid algorithm OID"));
    }
}

/*
fn generate_csr_ed25519(
    keypair: &Keypair,
    subject: &RdnSequence,
) -> Result<CertReq, anyhow::Error> {
    let ed25519_oid = ObjectIdentifier::new(ED25519_OID)?;

    let pub_key = BitString::from_bytes(&keypair.public.to_bytes())
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
    let signature = keypair
        .sign_prehashed(prehashed, None)
        .with_context(|| "Failed to sign certificate content")?;

    let csr = CertReq {
        info: info,
        algorithm: AlgorithmIdentifier {
            oid: ed25519_oid,
            parameters: None,
        },
        signature: BitString::from_bytes(&signature.to_bytes())?,
    };

    Ok(csr)
}

fn generate_csr_dilithium5(
    pk: &PublicKey,
    sk: &SecretKey,
    subject: &RdnSequence,
) -> Result<CertReq, anyhow::Error> {
    let dilithium5_oid = ObjectIdentifier::new(DILITHIUM5_OID)?;

    let pub_key = BitString::from_bytes(&pk.clone().into_vec())
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
    let signature = pq_scheme.sign(&content, sk)?;

    let csr = CertReq {
        info: info,
        algorithm: AlgorithmIdentifier {
            oid: dilithium5_oid,
            parameters: None,
        },
        signature: BitString::from_bytes(&signature.into_vec())?,
    };

    Ok(csr)
}

pub fn generate_cert_requests(
    keys: &HybridKeyPair,
    info: &CertificateFields,
) -> Result<String, anyhow::Error> {
    let dilithium5_oid = ObjectIdentifier::new(DILITHIUM5_OID)?;

    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject: RdnSequence::default(),
        public_key: SubjectPublicKeyInfo { algorithm: (), subject_public_key: () },
        attributes: ()
    };

    let csr = CertReq {
        info: info,
        algorithm: AlgorithmIdentifier { oid: (), parameters: () },
        signature: ()
    };

    csr.to_pem(LineEnding::LF)
    Ok(String::from("TODO"))
}
*/

/// Store a keypair in a PKCS8 file with a password
fn store_keypair(
    prk: &[u8],
    pbk: &[u8],
    kind: KeyType,
    pwd: &String,
    path: &String,
) -> Result<(), anyhow::Error> {
    let params = match pbes2::Parameters::scrypt_aes256cbc(
        pkcs8::pkcs5::scrypt::Params::recommended(),
        &hex!("79d982e70df91a88"),
        &hex!("b2d02d78b2efd9dff694cf8e0af40925"),
    ) {
        Ok(p) => p,
        Err(e) => {
            return Err(anyhow!("Failed to generate scrypt parameter: {e}"));
        }
    };

    let (label, oid) = match kind {
        KeyType::CLASSIC => ("ENCRYPTED PRIVATE KEY", ObjectIdentifier::new(ED25519_OID)?),
        KeyType::PQ => (
            "ENCRYPTED PRIVATE KEY",
            ObjectIdentifier::new(DILITHIUM5_OID)?,
        ),
    };

    let pk_info = PrivateKeyInfo {
        algorithm: pkcs8::AlgorithmIdentifierRef {
            oid: oid,
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

    pk_encrypted.write_pem_file(path, label, LineEnding::LF)?;

    // Test to load saved keys

    // match test_key.load_keys(path, pwd) {
    //     Ok(r) => r,
    //     Err(e) => {
    //         log::error!("Failed to load back key: {e}");
    //         return Err(anyhow!("Failed to load back key: {e}"));
    //     }
    // };

    // log::debug!("PRK: {:?}", prk);
    // log::debug!("Saved PRK: {:?}", s_prk);

    Ok(())
}

pub trait KeysasKey<T> {
    fn load_keys(path: &String, pwd: &String) -> Result<T, anyhow::Error>;
    //fn save_keys(&self, path: &String) -> Result<()>;
    fn generate_csr(&self, subject: &RdnSequence) -> Result<CertReq, anyhow::Error>;
}

// Implementing new methods on top of dalek Keypair
impl KeysasKey<Keypair> for Keypair {
    fn load_keys(path: &String, pwd: &String) -> Result<Keypair, anyhow::Error> {
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
            info: info,
            algorithm: AlgorithmIdentifier {
                oid: ed25519_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature.to_bytes())?,
        };

        Ok(csr)
    }
}

impl KeysasKey<KeysasPQKey> for KeysasPQKey {
    fn load_keys(path: &String, pwd: &String) -> Result<KeysasPQKey, anyhow::Error> {
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
            None => return Err(anyhow!("No PQC public key found in pkcs#8 format")),
        };
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
            info: info,
            algorithm: AlgorithmIdentifier {
                oid: dilithium5_oid,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature.into_vec())?,
        };
    
        Ok(csr)
    }
}
