use anyhow::anyhow;
use std::fs;

use keysas_lib::keysas_key::{KeysasHybridPubKeys, PublicKeys};

use crate::Config;
use crate::controller::SecurityPolicy;

pub fn load_security_policy(config: &Config) -> Result<SecurityPolicy, anyhow::Error> {
    // Load administration security policy
    let config_path = std::env::current_dir()?;
    // config_path.push(&config.config);
    // &config.config
    let config_toml = match fs::read_to_string(&config.config) {
        Ok(s) => s,
        Err(e) => {
            let cur_env = std::env::current_exe().unwrap();
            let exe_path = cur_env.to_str().unwrap();
            return Err(anyhow!("Failed to read configuration file {:#?} from {:#?}: {e}",
                &config.config,
                config_path.to_string_lossy()
            ));
        }
    };

    let policy: SecurityPolicy = match toml::from_str(&config_toml) {
        Ok(p) => p,
        Err(e) => {
            return Err(anyhow!(
                "Failed to parse configuration file {:#?}: {e}",
                &config.config
            ));
        }
    };

    Ok(policy)
}

pub fn load_certificates(config: &Config)
        -> Result<(KeysasHybridPubKeys, KeysasHybridPubKeys), anyhow::Error> {
    let st_ca_pub = match KeysasHybridPubKeys::get_pubkeys_from_certs(
                                                &config.ca_cert_cl,
                                                &config.ca_cert_pq) {
        Ok(Some(pk)) => pk,
        Ok(None) => {
            return Err(anyhow!("No public key found in station CA certificates"));
        },
        Err(e) => {
            return Err(anyhow!("Failed to extract station CA certificates: {e}"));
        }
    };

    let usb_ca_pub = match KeysasHybridPubKeys::get_pubkeys_from_certs(
                                                    &config.usb_ca_cl,
                                                    &config.usb_ca_pq) {
        Ok(Some(pk)) => pk,
        Ok(None) => {
            return Err(anyhow!("No public key found in USB CA certificates"));
        },
        Err(e) => {
            return Err(anyhow!("Failed to extract USB CA certificates: {e}"));
        }
    };

    Ok((st_ca_pub, usb_ca_pub))
}