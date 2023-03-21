use ed25519_dalek::Digest;
use ed25519_dalek::Sha512;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::HasPrivate;
use openssl::pkey::PKey;
use openssl::pkey::PKeyRef;
use openssl::pkey::Private;
use openssl::x509::X509;
use openssl::x509::X509Builder;
use openssl::x509::X509ReqRef;
use oqs::sig::Algorithm;
use oqs::sig::PublicKey;
use oqs::sig::SecretKey;
use oqs::sig::Sig;
use pkcs8::LineEnding;
use pkcs8::PrivateKeyInfo;
use pkcs8::pkcs5::pbes2;
use rand::rngs::OsRng;
use x509_cert::der::Decode;
use x509_cert::der::Encode;
use x509_cert::der::EncodePem;
use x509_cert::der::asn1::BitString;
use x509_cert::name::RdnSequence;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::AlgorithmIdentifier;
use x509_cert::spki::ObjectIdentifier;
use x509_cert::spki::SubjectPublicKeyInfo;
use x509_cert::time::Validity;
use std::fs;
use std::fs::File;
use std::fs::read;
use std::path::Path;
use std::error::Error;
use std::time::Duration;
use x509_cert::certificate::*;
use ed25519_dalek::Keypair;
use anyhow::anyhow;
use hex_literal::hex;
use std::io::Write;

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
pub struct CertificateFields {
    pub org_name: String,
    pub org_unit: String,
    pub country: String,
    pub validity: u32
}

pub struct HybridKeyPair {
    classic: Keypair,
    classic_cert: Certificate,
    pq_priv: SecretKey,
    pq_pub: PublicKey,
    pq_cert: Certificate
}

enum KEY_TYPE {
    CLASSIC,
    PQ
}

/// Validate user input and construct a certificate fields structure that can be used
/// to build the certificates of the PKI.
/// The checks done are :
///     - Test if country is 2 letters long, if less return error, if more shorten it to the first two letters
///     - Test if validity can be converted to u32, if not generate error
///     - Test if sigAlgo is either ed25519 or ed448, if not defaut to ed25519
pub fn validate_input_cert_fields<'a>(org_name: &'a String, org_unit: &'a String,
                                    country: &'a String, validity: &'a String)
                                    -> Result<CertificateFields, ()> {
    // Test if country is 2 letters long
    let cn = match country.len() {
        0 | 1 => return Err(()),
        2 => country.to_string(),
        _ => country[..2].to_string()
    };
    // Test if validity can be converted to u32
    let val = match validity.parse::<u32>() {
        Ok(v) => v,
        Err(_) => return Err(())
    };

    Ok(CertificateFields {
        org_name: org_name.to_string(),
        org_unit: org_unit.to_string(),
        country: cn,
        validity: val
    })
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

    fs::create_dir(pki_dir.to_owned() + "/CA")?;
    fs::create_dir(pki_dir.to_owned() + "/CA/root")?;
    fs::create_dir(pki_dir.to_owned() + "/CA/st")?;
    fs::create_dir(pki_dir.to_owned() + "/CA/usb")?;

    fs::create_dir(pki_dir.to_owned() + "/CRL")?;
    fs::create_dir(pki_dir.to_owned() + "/CERT")?;

    Ok(())
}

fn construct_tbs_certificate(infos:  &CertificateFields, pub_value: &[u8],
                                algo_oid: &ObjectIdentifier) -> Result<TbsCertificate, anyhow::Error> {
    let dur = Duration::new((infos.validity*60*60*24).into(), 0);

    let issuer_name = RdnSequence::encode_from_string("test")?;
    let subject_name = RdnSequence::encode_from_string("test")?;

    let pub_key = BitString::from_bytes(pub_value)?;
    let pub_key_info = SubjectPublicKeyInfo {
        algorithm: AlgorithmIdentifier { oid: *algo_oid, parameters: None },
        subject_public_key: pub_key,
    };

    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[1])?,
        signature: AlgorithmIdentifier{oid: *algo_oid, parameters: None},
        issuer: RdnSequence::from_der(&issuer_name)?,
        validity: Validity::from_now(dur)?,
        subject: RdnSequence::from_der(&subject_name)?,
        subject_public_key_info: pub_key_info,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None
    };
    Ok(tbs)
}

/// Generate the root certificate of the PKI from a private key and information
/// fields
/// The function returns the certificate or an openssl error
pub fn generate_root_ed25519(infos:  &CertificateFields)
                            -> Result<(Keypair, Certificate), anyhow::Error> {

    // Create the root CA Ed25519 key pair
    let mut csprng = OsRng{};
    let keypair = Keypair::generate(&mut csprng);
    let ed25519_oid = ObjectIdentifier::new("1.3.101.112")?;

    let tbs = construct_tbs_certificate(infos, 
                                &keypair.public.to_bytes(),
                            &ed25519_oid)?;
    let content = tbs.to_der()?;

    let mut prehashed = Sha512::new();
    prehashed.update(content);
    let sig = keypair.sign_prehashed(prehashed, None)?;

    let ed25519_oid = ObjectIdentifier::new("1.3.101.112")?;
    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: AlgorithmIdentifier{oid: ed25519_oid, parameters: None},
        signature: BitString::from_bytes(&sig.to_bytes())?,
    };

    Ok((keypair, cert))
}

pub fn generate_root_dilithium(infos:  &CertificateFields)
    -> Result<(SecretKey, PublicKey, Certificate), anyhow::Error> {
    // Create the root CA Dilithiul key pair
    let pq_scheme = Sig::new(Algorithm::Dilithium5)?;
    let (pk, sk) = pq_scheme.keypair()?;

    // OID value for dilithium-sha512 from IBM's networking OID range
    let dilithium5_oid = ObjectIdentifier::new("1.3.6.1.4.1.2.267.3")?;
    let tbs = construct_tbs_certificate(infos, 
                                &pk.clone().into_vec(),
                            &dilithium5_oid)?;
    let content = tbs.to_der()?;

    let signature = pq_scheme.sign(&content, &sk)?;

    let cert = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: AlgorithmIdentifier{oid: dilithium5_oid, parameters: None},
        signature: BitString::from_bytes(&signature.into_vec())?,
    };

    Ok((sk, pk, cert))
}

/// Generate PKI root keys
pub fn generate_root(infos: &CertificateFields, pki_dir: &String, pwd: &String)
    -> Result<HybridKeyPair, anyhow::Error> {

    // Generate root ED25519 key and certificate
    let (kp_ed, cert_ed) = generate_root_ed25519(&infos)?;

    // Generate root Dilithium key and certificate
    let (sk_dl, pk_dl, cert_dl) = generate_root_dilithium(&infos)?;

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
        KEY_TYPE::CLASSIC,
        pwd,
        &(pki_dir.to_owned() + "/CA/root-priv-cl.p8"))?;
    
    store_keypair(
        hk.pq_priv.as_ref(),
        hk.pq_pub.as_ref(),
        KEY_TYPE::PQ,
        pwd,
        &(pki_dir.to_owned() + "/CA/root-priv-pq.p8"))?;

    // Save certificate pair to disk
    let mut out_cl = File::create(pki_dir.to_owned() + "/CA/root-cert-cl.pem")?;
    write!(out_cl, "{}", hk.classic_cert.to_pem(LineEnding::LF)?)?;

    let mut out_pq = File::create(pki_dir.to_owned() + "/CA/root-cert-pq.pem")?;
    write!(out_pq, "{}", hk.pq_cert.to_pem(LineEnding::LF)?)?;

    Ok(hk)
}

/*
/// Generate a certification request for a public key
pub fn generate_cert_request<T: HasPublic + HasPrivate>(key: &PKeyRef<T>,
                                                        infos: &CertificateFields)
                                            -> Result<X509Req, ErrorStack>{
    let mut builder = X509ReqBuilder::new()?;
    
    // Set version
    builder.set_version(2)?;

    // Set subject name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, &infos.org_name)?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, &infos.org_unit)?;
    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, &infos.country)?;
    let name = name_builder.build();
    builder.set_subject_name(name.as_ref())?;

    // Set public key
    let raw_pub = key.raw_public_key()?;
    let pub_key = PKey::public_key_from_raw_bytes(&raw_pub, key.id())?;
    builder.set_pubkey(pub_key.as_ref())?;

    // Set request
    builder.sign(key, MessageDigest::null())?;

    Ok(builder.build())
}
*/

/// Generate a certificate from a request
pub fn generate_cert_from_request<T: HasPrivate>(req: &X509ReqRef,
                                                root_key: &PKeyRef<T>)
                                            -> Result<X509, ErrorStack>{
    // Get the public key
    let pub_key = req.public_key()?;
    
    // Verify the request
    if !req.verify(&pub_key)? {
        log::error!("Wrong request signature");
        return Err(ErrorStack::get());
    }

        //let rd = match BigNum::new_secure()
    let mut builder = X509Builder::new()?;

    builder.set_version(2)?;

    builder.set_pubkey(&pub_key)?;

    builder.sign(root_key, MessageDigest::null())?;

    Ok(builder.build())
}

/// Store a keypair in a PKCS8 file with a password
fn store_keypair(prk: &[u8], pbk: &[u8], kind: KEY_TYPE, pwd: &String, path: &String) -> Result<(), anyhow::Error> {
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
        KEY_TYPE::CLASSIC => {
            ("ED25519", ObjectIdentifier::new("1.3.101.112")?)
        },
        KEY_TYPE::PQ => {
            ("Dilithium5", ObjectIdentifier::new("1.3.6.1.4.1.2.267.3")?)
        }
    };

    let pk_info = PrivateKeyInfo {
        algorithm: pkcs8::AlgorithmIdentifier{oid: oid, parameters: None},
        private_key: prk,
        public_key: Some(pbk) 
    };

    let pk_encrypted = pk_info.encrypt_with_params(params, pwd)?;

    pk_encrypted.write_pem_file(path, label, LineEnding::LF)?;

    Ok(())
}

/*
/// Store a key and its certificate in a PKCS#12 file
pub fn store_pkcs12<T: HasPrivate>(pass: &String, name: &String,
                                key: &PKeyRef<T>, cert: &X509Ref,
                                path: &String)
                                -> Result<(), Box<dyn Error>> {
    let builder = Pkcs12::builder();
    //builder.key_algorithm(Nid::AES_256_GCM);
    //builder.cert_algorithm(Nid::AES_256_GCM);
    let pk = builder.build(pass, name, key, cert)?;
    let der = pk.to_der()?;
    let mut out = File::create(path)?;
    out.write_all(&der)?;
    Ok(())
}
*/

/// Load a key and a certificate from a PKCS#12 file
pub fn load_pkcs12(path: &String, pass: &String)
                -> Result<(PKey<Private>, X509), Box<dyn Error>> {
    let der = read(Path::new(path))?;
    let pk12 = Pkcs12::from_der(&der)?;
    let parsed = pk12.parse(pass)?;
    Ok((parsed.pkey, parsed.cert))
}

/*
/// Generate a private key and the corresponding certificate signed with the root key
pub fn generate_signed_keypair<T: HasPrivate>(root_key: &PKeyRef<T>,
                                                infos: &CertificateFields)
                            -> Result<(PKey<Private>, X509), ErrorStack> {
    // Generate private key
    let key =  PKey::generate_ed25519()?;

    // Generate certification request
    let req = generate_cert_request(key.as_ref(), infos)?;

    // Generate certificate
    let cert = generate_cert_from_request(&req, root_key)?;

    Ok((key, cert))
}
*/