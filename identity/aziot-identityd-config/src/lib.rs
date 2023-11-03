// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::large_enum_variant
)]

use std::collections::BTreeMap;
use std::io::ErrorKind;

use serde::{Deserialize, Serialize};

mod check;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Settings {
    pub hostname: String,

    pub homedir: std::path::PathBuf,

    #[serde(default)]
    pub prefer_module_identity_cache: bool,

    /// Maximum number of simultaneous requests per user that identityd will service.
    #[serde(
        default = "http_common::Incoming::default_max_requests",
        skip_serializing_if = "http_common::Incoming::is_default_max_requests"
    )]
    pub max_requests: usize,

    #[serde(
        default = "Settings::default_cloud_timeout",
        deserialize_with = "deserialize_cloud_timeout",
        skip_serializing_if = "Settings::is_default_timeout"
    )]
    pub cloud_timeout_sec: u64,

    #[serde(
        default = "Settings::default_cloud_retries",
        skip_serializing_if = "Settings::is_default_retries"
    )]
    pub cloud_retries: u32,

    pub provisioning: Provisioning,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal: Vec<Principal>,

    /// Only configurable in debug builds for the sake of tests.
    #[serde(default, skip_serializing)]
    #[cfg_attr(not(debug_assertions), serde(skip_deserializing))]
    pub endpoints: Endpoints,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub localid: Option<LocalId>,
}

impl Settings {
    pub fn default_cloud_timeout() -> u64 {
        70
    }

    pub fn default_cloud_retries() -> u32 {
        1
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn is_default_timeout(timeout: &u64) -> bool {
        *timeout == Settings::default_cloud_timeout()
    }

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn is_default_retries(retries: &u32) -> bool {
        *retries == Settings::default_cloud_retries()
    }
}

pub fn deserialize_cloud_timeout<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let result: u64 = Deserialize::deserialize(deserializer)?;

    if result < 70 {
        return Err(serde::de::Error::custom(
            "cloud_timeout_sec must be at least 70 seconds",
        ));
    }

    Ok(result)
}

#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub struct Principal {
    pub uid: Credentials,

    pub name: aziot_identity_common::ModuleId,

    #[serde(rename = "idtype")]
    pub id_type: Option<Vec<aziot_identity_common::IdType>>,

    /// Options for this principal's local identity.
    pub localid: Option<aziot_identity_common::LocalIdOpts>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialOrd, PartialEq, Deserialize, Serialize)]
pub struct Uid(pub libc::uid_t);

pub type Credentials = Uid;

/// Global options for all local identities.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct LocalId {
    /// Identifier for a group of local identity certificates, suffixed to the common name.
    pub domain: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "method")]
#[serde(rename_all = "lowercase")]
pub enum ManualAuthMethod {
    #[serde(rename = "sas")]
    SharedPrivateKey { device_id_pk: String },
    X509 {
        identity_cert: String,
        identity_pk: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        csr_subject: Option<CsrSubject>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum CsrSubject {
    CommonName(String),
    #[serde(deserialize_with = "subject_from_key_value")]
    Subject {
        #[serde(rename(serialize = "CN"))]
        cn: String,
        #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
        rest: BTreeMap<String, String>,
    },
}

impl CsrSubject {
    pub fn common_name(&self) -> &str {
        match self {
            Self::CommonName(cn) | Self::Subject { cn, .. } => cn,
        }
    }
}

fn subject_from_key_value<'de, D>(de: D) -> Result<(String, BTreeMap<String, String>), D::Error>
where
    D: serde::Deserializer<'de>,
{
    let mut res = BTreeMap::<String, String>::deserialize(de)?
        .into_iter()
        .map(|(k, v)| (k.to_uppercase(), v))
        .collect::<BTreeMap<_, _>>();
    Ok((
        res.remove("CN")
            .ok_or_else(|| <D::Error as serde::de::Error>::missing_field("CN"))?,
        res,
    ))
}

impl TryFrom<&CsrSubject> for openssl::x509::X509Name {
    type Error = openssl::error::ErrorStack;

    fn try_from(subject: &CsrSubject) -> Result<Self, Self::Error> {
        // X.509 requires CNs to be shorter than 64 characters.
        const CN_MAX_LENGTH: usize = 64;

        let mut builder = openssl::x509::X509Name::builder()?;

        match subject {
            CsrSubject::CommonName(cn) => {
                let mut cn = cn.to_string();
                cn.truncate(CN_MAX_LENGTH);
                builder.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, &cn)?;
            }
            CsrSubject::Subject { cn, rest } => {
                let mut cn = cn.to_string();
                cn.truncate(CN_MAX_LENGTH);
                builder.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, &cn)?;
                for (name, value) in rest {
                    builder.append_entry_by_text(name, value)?;
                }
            }
        }

        Ok(builder.build())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase", tag = "method")]
pub enum DpsAttestationMethod {
    #[serde(rename = "symmetric_key")]
    SymmetricKey {
        registration_id: String,
        symmetric_key: String,
    },
    X509 {
        identity_cert: String,
        identity_pk: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        registration_id: Option<CsrSubject>,
        #[serde(skip_serializing_if = "Option::is_none")]
        identity_auto_renew: Option<cert_renewal::AutoRenewConfig>,
    },
    Tpm {
        registration_id: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub struct Provisioning {
    pub local_gateway_hostname: Option<String>,

    #[serde(flatten)]
    pub provisioning: ProvisioningType,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "source")]
#[serde(rename_all = "lowercase")]
pub enum ProvisioningType {
    Manual {
        iothub_hostname: String,
        device_id: String,
        authentication: ManualAuthMethod,
    },
    Dps {
        global_endpoint: url::Url,
        scope_id: String,
        attestation: DpsAttestationMethod,
        #[serde(skip_serializing_if = "Option::is_none")]
        payload: Option<Payload>,
    },
    /// Disables provisioning with IoT Hub for devices that use local identities only.
    None,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub struct Payload {
    pub uri: url::Url,
}

impl Payload {
    /// Reads the payload from the file specified by the uri, returning the `serde_json::Value` representation
    pub fn serde_json_value(&self) -> Result<serde_json::Value, std::io::Error> {
        let url = url::Url::parse(self.uri.as_ref())
            .map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))?;
        if url.scheme() != "file" {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "payload uri is not a file",
            ));
        }
        let content = std::fs::read_to_string(url.to_file_path().map_err(|()| {
            std::io::Error::new(ErrorKind::InvalidInput, "payload uri is not a file path")
        })?)
        .map_err(|err| std::io::Error::new(ErrorKind::Other, err))?;

        serde_json::from_str::<serde_json::Value>(content.as_str())
            .map_err(|err| std::io::Error::new(ErrorKind::InvalidInput, err))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Endpoints {
    pub aziot_certd: http_common::Connector,
    pub aziot_identityd: http_common::Connector,
    pub aziot_keyd: http_common::Connector,
    pub aziot_tpmd: http_common::Connector,
}

impl Default for Endpoints {
    fn default() -> Self {
        Endpoints {
            aziot_certd: http_common::Connector::Unix {
                socket_path: std::path::Path::new("/run/aziot/certd.sock").into(),
            },
            aziot_identityd: http_common::Connector::Unix {
                socket_path: std::path::Path::new("/run/aziot/identityd.sock").into(),
            },
            aziot_keyd: http_common::Connector::Unix {
                socket_path: std::path::Path::new("/run/aziot/keyd.sock").into(),
            },
            aziot_tpmd: http_common::Connector::Unix {
                socket_path: std::path::Path::new("/run/aziot/tpmd.sock").into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Payload;

    use super::{DpsAttestationMethod, ManualAuthMethod, ProvisioningType, Settings};

    fn load_settings(
        filename: impl AsRef<std::path::Path>,
    ) -> Result<Settings, Box<dyn std::error::Error>> {
        let settings = std::fs::read_to_string(filename)?;
        let settings = toml::from_str(&settings)?;
        Ok(settings)
    }

    #[test]
    fn manual_sas_provisioning_settings_succeeds() {
        let s = load_settings("test/good_sas_config.toml").unwrap();

        if !matches!(
            s.provisioning.provisioning,
            ProvisioningType::Manual {
                authentication: ManualAuthMethod::SharedPrivateKey { .. },
                ..
            }
        ) {
            panic!("incorrect provisioning type selected");
        }
    }

    #[test]
    fn manual_dps_provisioning_settings_succeeds() {
        let s = load_settings("test/good_dps_config.toml").unwrap();

        if !matches!(
            s.provisioning.provisioning,
            ProvisioningType::Dps {
                attestation: DpsAttestationMethod::SymmetricKey { .. },
                ..
            }
        ) {
            panic!("incorrect provisioning type selected");
        }
    }

    // Checks for successful parsing of a config file containing a 'payload' in the 'provisioning' table
    fn check_payload(config_filename: &str, expected_payload: &Option<Payload>) {
        let s = load_settings(config_filename).unwrap();

        let ProvisioningType::Dps {
            payload: actual_payload,
            ..
        } = s.provisioning.provisioning
        else {
            panic!("wrong provisioning type specified in test config file")
        };

        assert_eq!(
            expected_payload, &actual_payload,
            "unexpected payload uri parsed from config file"
        );
    }

    #[test]
    fn dps_provisioning_with_simple_payload_succeeds() {
        std::fs::copy("test/simple_payload.json", "/tmp/simple_payload.json").unwrap();

        // TODO: Append payload uri to config file here, instead of hardcoding the value in the config file

        let config_filename = "test/good_dps_config_with_simple_payload.toml";
        let expected_payload = Some(Payload {
            uri: url::Url::parse("file:///tmp/simple_payload.json").unwrap(),
        });

        check_payload(config_filename, &expected_payload);
    }

    #[test]
    fn dps_provisioning_with_complex_payload_succeeds() {
        std::fs::copy("test/complex_payload.json", "/tmp/complex_payload.json")
            .expect("invalid uri");

        // TODO: Append payload uri to config file here, instead of hardcoding the value in the config file

        let config_filename = "test/good_dps_config_with_complex_payload.toml";
        let expected_payload = Some(Payload {
            uri: url::Url::parse("file:///tmp/complex_payload.json").expect("invalid uri"),
        });

        check_payload(config_filename, &expected_payload);
    }

    #[test]
    fn bad_provisioning_settings_fails() {
        assert!(
            load_settings("test/bad_config.toml").is_err(),
            "provisioning settings read should fail"
        );
    }

    #[test]
    fn bad_local_id_settings_fails() {
        assert!(
            load_settings("test/bad_local_config.toml").is_err(),
            "bad_local_config.toml read should fail"
        );
    }
}
