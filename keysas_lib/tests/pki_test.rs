use ed25519_dalek::Digest;
use ed25519_dalek::Keypair;
use ed25519_dalek::Sha512;
use hex_literal::hex;
use keysas_lib::keysas_key::KeysasKey;
use keysas_lib::keysas_key::KeysasPQKey;
use oqs::sig::Algorithm;
use oqs::sig::Sig;
use pkcs8::der::Any;
use pkcs8::der::Encode;
use pkcs8::der::asn1::BitString;
use pkcs8::pkcs5::pbes2;
use pkcs8::EncryptedPrivateKeyInfo;
use pkcs8::PrivateKeyInfo;
use pkcs8::spki::AlgorithmIdentifier;
use rand_dl::rngs::OsRng;
use tempfile::NamedTempFile;
use x509_cert::name::RdnSequence;
use std::fs::read;
use x509_cert::spki::ObjectIdentifier;

#[cfg(test)]

const PASSWORD: &[u8] = b"hunter42";

#[test]
fn test_pkcs8_decrypt_der() {
    let cipher: &[u8] = include_bytes!("./ed25519-encpriv-aes256-scrypt.der");
    let plain: &[u8] = include_bytes!("./ed25519-priv-pkcs8v1.der");

    let enc_pk = EncryptedPrivateKeyInfo::try_from(cipher).unwrap();

    let pk = enc_pk.decrypt(PASSWORD).unwrap();

    assert_eq!(pk.as_bytes(), plain);

    println!(
        "Secret document - length: {:?}, content: {:?}",
        pk.len(),
        pk.as_bytes()
    );
}

#[test]
fn test_pkcs8_create_and_decrypt_der() {
    // Create a random keypair
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);

    println!(
        "Test DER private only - Private key: {:?}",
        &keypair.secret.to_bytes()
    );
    println!(
        "Test DER private only  - Public key: {:?}",
        &keypair.public.to_bytes()
    );

    // Store the key as DER in PKCS8
    let file = NamedTempFile::new().unwrap();
    let path = file.into_temp_path();

    let params = pbes2::Parameters::scrypt_aes256cbc(
        pkcs8::pkcs5::scrypt::Params::recommended(),
        &hex!("79d982e70df91a88"),
        &hex!("b2d02d78b2efd9dff694cf8e0af40925"),
    )
    .unwrap();

    let oid = ObjectIdentifier::new("1.3.101.112").unwrap();

    let pk_info = PrivateKeyInfo {
        algorithm: pkcs8::AlgorithmIdentifierRef {
            oid: oid,
            parameters: None,
        },
        private_key: &keypair.secret.to_bytes(),
        public_key: None,
    };

    let pk_encrypted = pk_info.encrypt_with_params(params, PASSWORD).unwrap();

    pk_encrypted.write_der_file(&path).unwrap();

    // Load key from file
    let cipher = read(&path).unwrap();

    let enc_pk = EncryptedPrivateKeyInfo::try_from(cipher.as_slice()).unwrap();

    let sd = enc_pk.decrypt(PASSWORD).unwrap();
    println!(
        "Test DER private only  - Secret document - length: {:?}, content: {:?}",
        sd.len(),
        sd.as_bytes()
    );

    let pk: PrivateKeyInfo = sd.decode_msg().unwrap();
    println!(
        "Test DER private only  - Private key - content: {:?}",
        pk.private_key
    );

    assert_eq!(pk.private_key, keypair.secret.to_bytes());
}

#[test]
fn test_pkcs8_create_and_decrypt_with_public_der() {
    // Create a random keypair
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);

    println!(
        "Test DER with public - Private key: {:?}",
        &keypair.secret.to_bytes()
    );
    println!(
        "Test DER with public - Public key: {:?}",
        &keypair.public.to_bytes()
    );

    // Store the key as DER in PKCS8
    let file = NamedTempFile::new().unwrap();
    let path = file.into_temp_path();

    let params = pbes2::Parameters::scrypt_aes256cbc(
        pkcs8::pkcs5::scrypt::Params::recommended(),
        &hex!("79d982e70df91a88"),
        &hex!("b2d02d78b2efd9dff694cf8e0af40925"),
    )
    .unwrap();

    let oid = ObjectIdentifier::new("1.3.101.112").unwrap();

    let pub_value = keypair.public.to_bytes();

    let pk_info = PrivateKeyInfo {
        algorithm: pkcs8::AlgorithmIdentifierRef {
            oid: oid,
            parameters: None,
        },
        private_key: &keypair.secret.to_bytes(),
        public_key: Some(&pub_value),
    };

    let pk_encrypted = pk_info.encrypt_with_params(params, PASSWORD).unwrap();

    pk_encrypted.write_der_file(&path).unwrap();

    // Load key from file
    let cipher = read(&path).unwrap();

    let enc_pk = EncryptedPrivateKeyInfo::try_from(cipher.as_slice()).unwrap();

    let sd = enc_pk.decrypt(PASSWORD).unwrap();
    println!(
        "Test DER with public - Secret document - length: {:?}, content: {:?}",
        sd.len(),
        sd.as_bytes()
    );

    let pk: PrivateKeyInfo = sd.decode_msg().unwrap();
    println!(
        "Test DER with public - Private key - content: {:?}",
        pk.private_key
    );
    println!(
        "Test DER with public - Public key - content: {:?}",
        pk.public_key
    );

    assert_eq!(pk.private_key, keypair.secret.to_bytes());
    assert_eq!(pk.public_key.unwrap(), keypair.public.to_bytes());
}

#[test]
fn test_generate_csr_ed25519() {
    // Create a random keypair
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);

    // Generate a CSR
    let subject = RdnSequence::default();
    let csr = keypair.generate_csr(&subject).unwrap();

    // Test the CSR signature
    let info = csr.info.to_der().unwrap();
    let mut prehashed = Sha512::new();
    prehashed.update(info);
    let signature = keypair.sign_prehashed(prehashed, None).unwrap();

    assert_eq!(csr.signature, BitString::from_bytes(&signature.to_bytes()).unwrap());

    // Test CSR signing algorithm
    let ed25519_oid = ObjectIdentifier::new("1.3.101.112").unwrap();
    let ref_algo: AlgorithmIdentifier<Any> = AlgorithmIdentifier {
        oid: ed25519_oid,
        parameters: None
    };
    assert_eq!(csr.algorithm, ref_algo);

    // Test CSR Version number
    assert_eq!(csr.info.version, x509_cert::request::Version::V1);

    // Test CSR subject name
    assert_eq!(csr.info.subject, subject);

    // Test CSR public key value
    assert_eq!(csr.info.public_key.subject_public_key, BitString::from_bytes(&keypair.public.to_bytes()).unwrap());
    assert_eq!(csr.info.public_key.algorithm, ref_algo);

    // Test CSR attributes
    // The CSR must not contain any attribute
    assert_eq!(csr.info.attributes.len(), 0);
}

#[test]
fn test_generate_csr_dilithium5() {
    // Create the root CA Dilithium key pair
    oqs::init();
    let pq_scheme = Sig::new(Algorithm::Dilithium5).unwrap();
    let (pk, sk) = pq_scheme.keypair().unwrap();
    let keypair = KeysasPQKey {
        private_key: sk,
        public_key: pk.clone()
    };

    // Generate a CSR
    let subject = RdnSequence::default();
    let csr = keypair.generate_csr(&subject).unwrap();

    // Test the CSR signature
    match pq_scheme.verify(
        &csr.info.to_der().unwrap(),
        pq_scheme.signature_from_bytes(csr.signature.as_bytes().unwrap()).unwrap(),
        &keypair.public_key) {
        Ok(_) => assert!(true),
        Err(e) => assert!(false, "{}", e)
    }

    // Test CSR signing algorithm
    let dilithium5_oid = ObjectIdentifier::new("1.3.6.1.4.1.2.267.7.8.7").unwrap();
    let ref_algo: AlgorithmIdentifier<Any> = AlgorithmIdentifier {
        oid: dilithium5_oid,
        parameters: None
    };
    assert_eq!(csr.algorithm, ref_algo);

    // Test CSR Version number
    assert_eq!(csr.info.version, x509_cert::request::Version::V1);

    // Test CSR subject name
    assert_eq!(csr.info.subject, subject);

    // Test CSR public key value
    assert_eq!(csr.info.public_key.subject_public_key, BitString::from_bytes(&keypair.public_key.clone().into_vec()).unwrap());
    assert_eq!(csr.info.public_key.algorithm, ref_algo);

    // Test CSR attributes
    // The CSR must not contain any attribute
    assert_eq!(csr.info.attributes.len(), 0);
}

#[test]
fn test_save_and_load_ed25519() {
    // Create a random keypair
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);

    // Store the key as DER in PKCS8
    let file = NamedTempFile::new().unwrap();
    let path = file.into_temp_path();

    // Save the keypair
    keypair.save_keys(&path, &String::from("Test")).unwrap();

    // Load the keypair
    let loaded = Keypair::load_keys(&path, &String::from("Test")).unwrap();

    assert_eq!(loaded.secret.to_bytes(), keypair.secret.to_bytes());
    assert_eq!(loaded.public.to_bytes(), keypair.public.to_bytes());
}

#[test]
fn test_save_and_load_dilithium5() {
    // Create the root CA Dilithium key pair
    oqs::init();
    let pq_scheme = Sig::new(Algorithm::Dilithium5).unwrap();
    let (pk, sk) = pq_scheme.keypair().unwrap();
    let keypair = KeysasPQKey {
        private_key: sk,
        public_key: pk.clone()
    };

    // Store the key as DER in PKCS8
    let file = NamedTempFile::new().unwrap();
    let path = file.into_temp_path();

    // Save the keypair
    keypair.save_keys(&path, &String::from("Test")).unwrap();

    // Load the keypair
    let loaded = KeysasPQKey::load_keys(&path, &String::from("Test")).unwrap();

    assert_eq!(loaded.private_key.into_vec(), keypair.private_key.into_vec());
    assert_eq!(loaded.public_key.into_vec(), keypair.public_key.into_vec());
}