#[cfg(test)]

use std::fs::read;
use hex_literal::hex;
use pkcs8::EncryptedPrivateKeyInfo;
use pkcs8::pkcs5::pbes2;
use pkcs8::PrivateKeyInfo;
use x509_cert::spki::ObjectIdentifier;
use rand_dl::rngs::OsRng;
use ed25519_dalek::Keypair;
use tempdir::TempDir;

const PASSWORD: &[u8] = b"hunter42";

#[test]
fn test_pkcs8_decrypt_der() {
    let cipher: &[u8] = include_bytes!("./ed25519-encpriv-aes256-scrypt.der");
    let plain: &[u8] = include_bytes!("./ed25519-priv-pkcs8v1.der");

    let enc_pk = EncryptedPrivateKeyInfo::try_from(cipher).unwrap();

    let pk = enc_pk.decrypt(PASSWORD).unwrap();

    assert_eq!(pk.as_bytes(), plain);

    println!("Secret document - length: {:?}, content: {:?}", pk.len(), pk.as_bytes());
}

#[test]
fn test_pkcs8_create_and_decrypt_der() {
    // Create a random keypair
    let mut csprng = OsRng{};
    let keypair = Keypair::generate(&mut csprng);

    println!("Test create - Private key: {:?}", &keypair.secret.to_bytes());
    println!("Test create - Public key: {:?}", &keypair.public.to_bytes());

    // Store the key as DER in PKCS8
    let dir = TempDir::new("Test_DER").unwrap();
    let path = dir.path().join("priv.der");

    let params = pbes2::Parameters::scrypt_aes256cbc(
        pkcs8::pkcs5::scrypt::Params::recommended(),
        &hex!("79d982e70df91a88"),
        &hex!("b2d02d78b2efd9dff694cf8e0af40925"),).unwrap();
    
    let oid = ObjectIdentifier::new("1.3.101.112").unwrap();

    let pk_info = PrivateKeyInfo {
        algorithm: pkcs8::AlgorithmIdentifierRef{oid: oid, parameters: None},
        private_key: &keypair.secret.to_bytes(),
        public_key: None
    };

    let pk_encrypted = pk_info.encrypt_with_params(
        params,
        PASSWORD).unwrap();

    pk_encrypted.write_der_file(&path).unwrap();

    // Load key from file
    let cipher = read(&path).unwrap();

    let enc_pk = EncryptedPrivateKeyInfo::try_from(cipher.as_slice()).unwrap();

    let sd = enc_pk.decrypt(PASSWORD).unwrap();
    println!("Test create - Secret document - length: {:?}, content: {:?}", sd.len(), sd.as_bytes());

    let pk: PrivateKeyInfo = sd.decode_msg().unwrap();
    println!("Test create - Private key - content: {:?}", pk.private_key);

    assert_eq!(pk.private_key, keypair.secret.to_bytes());


    dir.close().unwrap();
}