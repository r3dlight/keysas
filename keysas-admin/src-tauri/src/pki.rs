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
use std::error::Error;
use std::fs::read;
use std::path::Path;

/// Structure containing informations to build the certificate
pub struct CertificateFields {
    pub validity: u32
}

/// Generate the root certificate of the PKI from a private key and information
/// fields
/// The function returns the certificate or an openssl error
pub fn generate_root_cert<T: HasPublic + HasPrivate>(key: &PKeyRef<T>,
                                            fields:  &CertificateFields)
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
    let end = Asn1Time::days_from_now(fields.validity)?;
    cert_builder.set_not_after(end.as_ref())?;

    // - Issuer name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, "FR")?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, "ANSSI")?;
    cert_builder.set_issuer_name(name_builder.build().as_ref())?;

    // - Subject name
    let mut name_builder = X509NameBuilder::new()?;
    name_builder.append_entry_by_nid(Nid::COUNTRYNAME, "FR")?;
    name_builder.append_entry_by_nid(Nid::ORGANIZATIONNAME, "ANSSI")?;
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
pub fn generate_cert_request<T: HasPublic + HasPrivate>(key: &PKeyRef<T>)
                                            -> Result<X509Req, ErrorStack>{
    let mut builder = X509ReqBuilder::new()?;

    builder.set_version(2)?;
    let raw_pub = key.raw_public_key()?;
    let pub_key = PKey::public_key_from_raw_bytes(&raw_pub, key.id())?;
    builder.set_pubkey(pub_key.as_ref())?;

    builder.sign(key, MessageDigest::null())?;

    Ok(builder.build())
}

/// Generate a certificate from a request
pub fn generate_cert_from_request<T: HasPrivate, U: HasPublic>(req: &X509ReqRef,
                                                pub_key: &PKeyRef<U>,
                                                root_key: &PKeyRef<T>)
                                            -> Result<X509, ErrorStack>{
    // Verify the request
    if !req.verify(pub_key)? {
        println!("Wrong request signature");
        return Err(ErrorStack::get());
    }

    let mut builder = X509Builder::new()?;

    builder.set_version(2)?;

    builder.set_pubkey(pub_key)?;

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
pub fn generate_signed_keypair<T: HasPrivate>(root_key: &PKeyRef<T>)
                            -> Result<(PKey<Private>, X509), ErrorStack> {
    // Generate private key
    let usb_key = PKey::generate_ed25519()?;

    // Generate certification request
    let usb_req = generate_cert_request(usb_key.as_ref())?;

    // Generate certificate
    let pub_usb_raw = usb_key.raw_public_key()?;

    let pub_usb = PKey::public_key_from_raw_bytes(&pub_usb_raw, usb_key.id())?;

    let usb_cert = generate_cert_from_request(&usb_req, pub_usb.as_ref(), root_key)?;

    Ok((usb_key, usb_cert))
}