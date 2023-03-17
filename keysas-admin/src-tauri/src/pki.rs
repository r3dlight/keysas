use openssl::asn1::Asn1Integer;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::HasPrivate;
use openssl::pkey::HasPublic;
use openssl::pkey::Id;
use openssl::pkey::PKey;
use openssl::pkey::PKeyRef;
use openssl::pkey::Private;
use openssl::x509::X509;
use openssl::x509::X509Builder;
use openssl::x509::X509NameBuilder;
use openssl::x509::X509Ref;
use openssl::x509::X509Req;
use openssl::x509::X509ReqBuilder;
use openssl::x509::X509ReqRef;

use std::fs::File;
use std::io::Write;
use std::fs::read;
use std::path::Path;
use std::error::Error;

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
    pub validity: u32,
    pub sig_algo: Id
}

/// Validate user input and construct a certificate fields structure that can be used
/// to build the certificates of the PKI.
/// The checks done are :
///     - Test if country is 2 letters long, if less return error, if more shorten it to the first two letters
///     - Test if validity can be converted to u32, if not generate error
///     - Test if sigAlgo is either ed25519 or ed448, if not defaut to ed25519
pub fn validate_input_cert_fields<'a>(org_name: &'a String, org_unit: &'a String,
                                    country: &'a String, validity: &'a String,
                                    sig_algo: &'a String)
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

    // Test if sigAlgo is either ed25519 or ed448, if not defaut to ed25519
    let algo = if sig_algo.eq("ed448") { Id::ED448 } else { Id::ED25519 };

    Ok(CertificateFields {
        org_name: org_name.to_string(),
        org_unit: org_unit.to_string(),
        country: cn,
        validity: val,
        sig_algo: algo
    })
}

/// Generate the root certificate of the PKI from a private key and information
/// fields
/// The function returns the certificate or an openssl error
pub fn generate_root_cert<T: HasPublic + HasPrivate>(key: &PKeyRef<T>,
                                            infos:  &CertificateFields)
                                            -> Result<X509, ErrorStack> {
    // Initiate certificate builder
    let mut cert_builder = X509Builder::new()?;

    // Set certificate fields
    // - Version
    cert_builder.set_version(2)?;

    // - Serial Number => First certificate: 1
    let num: u32 = 1;
    let bgn = BigNum::from_u32(num)?;
    let serial = Asn1Integer::from_bn(bgn.as_ref())?;
    cert_builder.set_serial_number(serial.as_ref())?;

    // - Validity dates
    let now = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(now.as_ref())?;
    let end = Asn1Time::days_from_now(infos.validity)?;
    cert_builder.set_not_after(end.as_ref())?;

    // - Issuer name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, &infos.country)?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, &infos.org_name)?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, &infos.org_unit)?;
    cert_builder.set_issuer_name(name_builder.build().as_ref())?;

    // - Subject name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, &infos.country)?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, &infos.org_name)?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONALUNITNAME, &infos.org_unit)?;
    cert_builder.set_subject_name(name_builder.build().as_ref())?;

    // - Public key
    let pub_raw = key.raw_public_key()?;
    let pub_key = PKey::public_key_from_raw_bytes(&pub_raw, key.id())?;
    cert_builder.set_pubkey(pub_key.as_ref())?;

    // Sign certificate
    // TODO: check if default hash algorithm is compatible with RGS
    cert_builder.sign(&key, MessageDigest::null())?;

    // Generate certificate
    Ok(cert_builder.build())
}

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

/// Load a key and a certificate from a PKCS#12 file
pub fn load_pkcs12(path: &String, pass: &String)
                -> Result<(PKey<Private>, X509), Box<dyn Error>> {
    let der = read(Path::new(path))?;
    let pk12 = Pkcs12::from_der(&der)?;
    let parsed = pk12.parse(pass)?;
    Ok((parsed.pkey, parsed.cert))
}

/// Generate a private key and the corresponding certifiacte signed with the root key
pub fn generate_signed_keypair<T: HasPrivate>(root_key: &PKeyRef<T>,
                                                infos: &CertificateFields)
                            -> Result<(PKey<Private>, X509), ErrorStack> {
    // Generate private key
    let key = match infos.sig_algo {
        Id::ED448 => PKey::generate_ed448()?,
        _ => PKey::generate_ed25519()?
    };

    // Generate certification request
    let req = generate_cert_request(key.as_ref(), infos)?;

    // Generate certificate
    let cert = generate_cert_from_request(&req, root_key)?;

    Ok((key, cert))
}