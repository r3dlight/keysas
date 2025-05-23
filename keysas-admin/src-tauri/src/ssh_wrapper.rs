use std::error::Error;
use std::net::TcpStream;

use ssh::LocalSession;
use ssh::SshResult;
use ssh::algorithm;
use ssh::create_session_without_default;

const TIMEOUT: u64 = 60 * 1000;
const USER: &str = "keysas";
const PASSWORD: &str = "Changeme007";

/// Create SSH connexion with RSA or ECC key
pub fn connect_key(ip: &str, private_key: &str) -> Result<LocalSession<TcpStream>, Box<dyn Error>> {
    let host = format!("{}{}", ip.trim(), ":22");
    let connector = create_session_without_default()
        .username(USER)
        .private_key_path(private_key.trim())
        .add_kex_algorithms(algorithm::Kex::Curve25519Sha256)
        .add_kex_algorithms(algorithm::Kex::EcdhSha2Nistrp256)
        .add_pubkey_algorithms(algorithm::PubKey::SshEd25519)
        .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_512)
        .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
        .add_enc_algorithms(algorithm::Enc::Chacha20Poly1305Openssh)
        .add_compress_algorithms(algorithm::Compress::None)
        .add_mac_algortihms(algorithm::Mac::HmacSha2_512)
        .add_mac_algortihms(algorithm::Mac::HmacSha2_256)
        .timeout(Some(std::time::Duration::from_secs(TIMEOUT)))
        .connect(host)?;
    let session = connector.run_local();
    Ok(session)
}

/// Create SSH connexion with password
pub fn connect_pwd(ip: &str) -> SshResult<LocalSession<TcpStream>> {
    let host = format!("{}{}", ip.trim(), ":22");
    let connector = create_session_without_default()
        .username(USER)
        .password(PASSWORD)
        .add_kex_algorithms(algorithm::Kex::Curve25519Sha256)
        .add_kex_algorithms(algorithm::Kex::EcdhSha2Nistrp256)
        .add_pubkey_algorithms(algorithm::PubKey::SshEd25519)
        .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_512)
        .add_pubkey_algorithms(algorithm::PubKey::RsaSha2_256)
        .add_enc_algorithms(algorithm::Enc::Chacha20Poly1305Openssh)
        .add_compress_algorithms(algorithm::Compress::None)
        .add_mac_algortihms(algorithm::Mac::HmacSha2_512)
        .add_mac_algortihms(algorithm::Mac::HmacSha2_256)
        .timeout(Some(std::time::Duration::from_secs(TIMEOUT)))
        .connect(host)?;
    let session = connector.run_local();
    Ok(session)
}

pub fn session_exec(
    session: &mut LocalSession<TcpStream>,
    command: &str,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let channel = session.open_exec()?;
    let output = channel.send_command(command)?;
    Ok(output)
}

pub fn session_upload(
    session: &mut LocalSession<TcpStream>,
    path_l: &str,
    path_d: &str,
) -> SshResult<()> {
    let channel = session.open_scp()?;
    channel.upload(path_l, path_d)
}
