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
 #![warn(unused_import_braces)] #![warn(unused_qualifications)]
 #![warn(variant_size_differences)]
 #![forbid(private_in_public)]
 #![warn(overflowing_literals)]
 #![warn(deprecated)]
 #![warn(unused_imports)]

 use anyhow::{anyhow, Context};
 use pkcs8::der::Encode;
use pkcs8::der::asn1::OctetString;
 use pkcs8::der::oid::db::rfc5280;
 use x509_cert::ext::Extension;
 use std::str::FromStr;
use std::time::Duration;
 use x509_cert::certificate::*;
 use x509_cert::der::asn1::BitString;
 use x509_cert::name::RdnSequence;
 use x509_cert::serial_number::SerialNumber;
 use x509_cert::spki::AlgorithmIdentifier;
 use x509_cert::spki::ObjectIdentifier;
 use x509_cert::spki::SubjectPublicKeyInfo;
 use x509_cert::time::Validity;

/// Structure containing informations to build the certificate
#[derive(Debug, Clone)]
pub struct CertificateFields {
    pub org_name:    Option<String>,
    pub org_unit:    Option<String>,
    pub country:     Option<String>,
    pub common_name: Option<String>,
    pub validity:    Option<u32>,
}

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
                0|1 => Err(anyhow!("Invalid country name")),
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
            name.push_str(cn);
            name.push(',');
        }

        // Add organisation name
        if let Some(oa) = &self.org_name {
            if name.chars().nth_back(0).is_some_and(|c| !c.eq(&',')) {
                name.push(',');
            }
            name.push_str("O=");
            name.push_str(oa);
            name.push(',');
        }

        // Add organisational unit
        if let Some(ou) = &self.org_unit {
            if name.chars().nth_back(0).is_some_and(|c| !c.eq(&',')) {
                name.push(',');
            }
            name.push_str("OU=");
            name.push_str(ou);
            name.push(',');
        }

        // Add common name
        if let Some(co) = &self.common_name {
            if name.chars().nth_back(0).is_some_and(|c| !c.eq(&',')) {
                name.push(',');
            }
            name.push_str("CN=");
            name.push_str(co);
            name.push(',');
        }

        // Remove trailing ',' if there is one
        if name.chars().nth_back(0).is_some_and(|c| !c.eq(&',')) {
            name.pop();
        }

        let rdn = RdnSequence::from_str(&name)?;
        Ok(rdn)
    }

    /// Construct a information field for a certificate using the issuer CertificateInfos
    /// and the subject name and key
    /// The serial number is supplied by the caller that must ensure its uniqueness
    pub fn construct_tbs_certificate(
        &self,
        subject_name: &RdnSequence,
        pub_value: &[u8],
        serial: &[u8],
        algo_oid: &ObjectIdentifier,
        is_app_cert: bool,
        ) -> Result<TbsCertificate, anyhow::Error> {
        // Convert input validity from days to seconds
        let dur = match self.validity {
            Some(value) => Duration::new((value * 60 * 60 * 24).into(), 0),
            None => {return Err(anyhow!("Invalid validity value"));}
        };
    
        // Create Distinguished Names for issuer and subject
        let issuer_name = self.generate_dn()?;
    
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
}