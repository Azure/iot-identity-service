// Copyright (c) Microsoft. All rights reserved.

use std::fmt::Display;
use std::path::Path;
use std::str::FromStr;


use crate::error::InternalError;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Settings {
    pub hostname: String,

    pub homedir: std::path::PathBuf,

    pub principal: Option<Vec<Principal>>,

    pub provisioning: Provisioning,

    pub endpoints: Endpoints,
}

impl Settings {
    pub fn new(filename: &Path) -> Result<Self, InternalError> {
        let settings = std::fs::read_to_string(filename).map_err(InternalError::LoadSettings)?;
        let settings = toml::from_str(&settings).map_err(InternalError::ParseSettings)?;

        Ok(settings)
    }
}

#[derive(Eq, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
pub struct DeviceInfo {
    pub hub_name: String,

    pub device_id: String,
}

impl DeviceInfo {
    pub fn new(filename: &Path)-> Result<Self, InternalError> {
        let info = std::fs::read_to_string(filename).map_err(InternalError::LoadDeviceInfo)?;
        let info = toml::from_str(&info).map_err(InternalError::ParseDeviceInfo)?;

        Ok(info)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all="lowercase")]
pub struct Principal {
    pub uid: crate::auth::Credentials,

    pub name: aziot_identity_common::ModuleId,
    #[serde(rename = "idtype")]
    pub id_type: Option<aziot_identity_common::IdType>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "method")]
#[serde(rename_all = "lowercase")]
pub enum ManualAuthMethod {
    #[serde(rename = "sas")]
    SharedPrivateKey {
        device_id_pk: String,
    },
    X509 {
        identity_cert: String,
        identity_pk: String,
    },
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "method")]
#[serde(rename_all = "lowercase")]
pub enum DpsAttestationMethod {
    #[serde(rename = "symmetric_key")]
    SymmetricKey {
        registration_id: String,
        symmetric_key: String,
    },
    X509 {
        registration_id: String,
        identity_cert: String,
        identity_pk: String,
    },
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub struct Provisioning {
    #[serde(flatten)]
    pub provisioning: ProvisioningType,

    #[serde(default)]
    pub dynamic_reprovisioning: bool,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "source")]
#[serde(rename_all = "lowercase")]
pub enum ProvisioningType {
    Manual {
        iothub_hostname: String,
        device_id: String,
        authentication: ManualAuthMethod,
    },
    Dps {
        global_endpoint: String,
        scope_id: String,
        attestation: DpsAttestationMethod,
    },
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Endpoints {
    pub aziot_certd: http_common::Connector,
    pub aziot_identityd: http_common::Connector,
    pub aziot_keyd: http_common::Connector,
}

//TODO: Keeping this setting around until it is determined HTTPS isn't supported
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Protocol {
    Tls10,
    Tls11,
    Tls12,
}

impl Default for Protocol {
    fn default() -> Self {
        Protocol::Tls10
    }
}

impl Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tls10 => write!(f, "TLS 1.0"),
            Protocol::Tls11 => write!(f, "TLS 1.1"),
            Protocol::Tls12 => write!(f, "TLS 1.2"),
        }
    }
}

impl FromStr for Protocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_ref() {
            "tls" | "tls1" | "tls10" | "tls1.0" | "tls1_0" | "tlsv10" => Ok(Protocol::Tls10),
            "tls11" | "tls1.1" | "tls1_1" | "tlsv11" => Ok(Protocol::Tls11),
            "tls12" | "tls1.2" | "tls1_2" | "tlsv12" => Ok(Protocol::Tls12),
            _ => Err(format!("Unsupported TLS protocol version: {}", s)),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Protocol {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Protocol {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
    }
}

#[cfg(test)]
mod tests {
    use test_case::test_case;
    use crate::settings::{ProvisioningType, Settings, DpsAttestationMethod, ManualAuthMethod};
    use super::{FromStr, Protocol};

    #[test]
    fn manual_sas_provisioning_settings_succeeds() {
        let s = Settings::new(std::path::Path::new("test/good_sas_config.toml")).unwrap();

        assert_eq!(s.provisioning.dynamic_reprovisioning, false);

        match s.provisioning.provisioning {
            ProvisioningType::Manual { iothub_hostname:_, device_id:_, authentication } => {
                match authentication {
                    ManualAuthMethod::SharedPrivateKey { 
                        device_id_pk: _,
                     } => {},
                    _ => panic!("incorrect provisioning type selected"),
                     
                }
            },
            _ => panic!("incorrect provisioning type selected"),
        };
    }

    #[test]
    fn manual_dps_provisioning_settings_succeeds() {
        let s = Settings::new(std::path::Path::new("test/good_dps_config.toml")).unwrap();

        match s.provisioning.provisioning {
            ProvisioningType::Dps {
                global_endpoint: _,
                scope_id: _,
                attestation,
            } => {
                match attestation {
                    DpsAttestationMethod::SymmetricKey {
                        registration_id: _,
                        symmetric_key: _,     
                    } => (),
                    _ => panic!("incorrect provisioning type selected"),
                }
            },
            _ => panic!("incorrect provisioning type selected"),
        };
    }

    #[test]
    fn bad_provisioning_settings_fails() {
        assert!(
            Settings::new(std::path::Path::new("test/bad_config.toml")).is_err(),
            "provisioning settings read should fail"
        );
    }

    #[test_case("tls", Protocol::Tls10; "when tls provided")]
    #[test_case("tls1", Protocol::Tls10; "when tls1 with dot provided")]
    #[test_case("tls10", Protocol::Tls10; "when tls10 provided")]
    #[test_case("tls1.0", Protocol::Tls10; "when tls10 with dot provided")]
    #[test_case("tls1_0", Protocol::Tls10; "when tls10 with underscore provided")]
    #[test_case("Tlsv10" , Protocol::Tls10; "when Tlsv10 provided")]
    #[test_case("TLS10", Protocol::Tls10; "when uppercase TLS10 Provided")]
    #[test_case("tls11", Protocol::Tls11; "when tls11 provided")]
    #[test_case("tls1.1", Protocol::Tls11; "when tls11 with dot provided")]
    #[test_case("tls1_1", Protocol::Tls11; "when tls11 with underscore provided")]
    #[test_case("Tlsv11" , Protocol::Tls11; "when Tlsv11 provided")]
    #[test_case("TLS11", Protocol::Tls11; "when uppercase TLS11 Provided")]
    #[test_case("tls12", Protocol::Tls12; "when tls12 provided")]
    #[test_case("tls1.2", Protocol::Tls12; "when tls12 with dot provided")]
    #[test_case("tls1_2", Protocol::Tls12; "when tls12 with underscore provided")]
    #[test_case("Tlsv12" , Protocol::Tls12; "when Tlsv12 provided")]
    #[test_case("TLS12", Protocol::Tls12; "when uppercase TLS12 Provided")]
    fn it_parses_protocol(value: &str, expected: Protocol) {
        let actual = Protocol::from_str(value);
        assert_eq!(actual, Ok(expected));
    }

    #[test_case(""; "when empty string provided")]
    #[test_case("Sslv3"; "when unsupported version provided")]
    #[test_case("TLS2"; "when non-existing version provided")]
    fn it_fails_to_parse_protocol(value: &str) {
        let actual = Protocol::from_str(value);
        assert_eq!(
            actual,
            Err(format!("Unsupported TLS protocol version: {}", value))
        )
    }
}
