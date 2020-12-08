// Copyright (c) Microsoft. All rights reserved.

use std::fmt::Display;
use std::path::Path;
use std::str::FromStr;

use crate::error::InternalError;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Settings {
    pub hostname: String,

    pub homedir: std::path::PathBuf,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal: Vec<Principal>,

    pub provisioning: Provisioning,

    /// Only configurable in debug builds for the sake of tests.
    #[serde(default, skip_serializing)]
    #[cfg_attr(not(debug_assertions), serde(skip_deserializing))]
    pub endpoints: Endpoints,

    pub localid: Option<LocalId>,
}

impl Settings {
    pub fn new(filename: &Path) -> Result<Self, InternalError> {
        let settings = std::fs::read_to_string(filename).map_err(InternalError::LoadSettings)?;
        let settings: Settings = toml::from_str(&settings).map_err(InternalError::ParseSettings)?;

        settings.check()
    }

    pub fn check(self) -> Result<Self, InternalError> {
        let mut existing_names: std::collections::BTreeSet<aziot_identity_common::ModuleId> =
            std::collections::BTreeSet::default();

        for p in &self.principal {
            if !existing_names.insert(p.name.clone()) {
                return Err(InternalError::BadSettings(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("duplicate module name: {}", p.name.0),
                )));
            }

            if let Some(t) = &p.id_type {
                if t.contains(&aziot_identity_common::IdType::Local) {
                    // Require localid in config if any principal has local id_type.
                    if self.localid.is_none() {
                        return Err(InternalError::BadSettings(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "invalid config for {}: local id type requires localid config",
                                p.name.0
                            ),
                        )));
                    }
                } else {
                    // Reject principals that specify local identity options without the "local" type.
                    if p.localid.is_some() {
                        return Err(InternalError::BadSettings(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("invalid config for {}: local identity options specified for non-local identity", p.name.0)
                        )));
                    }
                }

                // Require provisioning if any module or device identities are present.
                let provisioning_valid = match self.provisioning.provisioning {
                    ProvisioningType::None => {
                        !t.contains(&aziot_identity_common::IdType::Module)
                            && !t.contains(&aziot_identity_common::IdType::Device)
                    }
                    _ => true,
                };

                if !provisioning_valid {
                    return Err(InternalError::BadSettings(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!("invalid config for {}: module or device identity requires provisioning with IoT Hub", p.name.0)
                        ))
                    );
                }
            }
        }

        Ok(self)
    }
}

#[derive(Debug, Eq, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
pub struct HubDeviceInfo {
    pub hub_name: String,

    pub device_id: String,
}

impl HubDeviceInfo {
    pub fn new(filename: &Path) -> Result<Option<Self>, InternalError> {
        let info = std::fs::read_to_string(filename).map_err(InternalError::LoadDeviceInfo)?;

        let info = match info.as_str() {
            "unprovisioned" => None,
            _ => Some(toml::from_str(&info).map_err(InternalError::ParseDeviceInfo)?),
        };

        Ok(info)
    }

    pub fn unprovisioned() -> String {
        "unprovisioned".to_owned()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub struct Principal {
    pub uid: crate::auth::Credentials,

    pub name: aziot_identity_common::ModuleId,

    #[serde(rename = "idtype")]
    pub id_type: Option<Vec<aziot_identity_common::IdType>>,

    /// Options for this principal's local identity.
    pub localid: Option<LocalIdOpts>,
}

/// Global options for all local identities.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct LocalId {
    /// Identifier for a group of local identity certificates, suffixed to the common name.
    pub domain: String,
}

/// Options for a single local identity.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(tag = "type")]
pub enum LocalIdOpts {
    /// Options valid when local identities are X.509 credentials. Currently the only
    /// supported credential type, but may change in the future.
    #[serde(rename = "x509")]
    X509 {
        /// Whether the X.509 certificate is a TLS client or server certificate.
        #[serde(default)]
        attributes: aziot_identity_common::LocalIdAttr,
    },
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "method")]
#[serde(rename_all = "lowercase")]
pub enum ManualAuthMethod {
    #[serde(rename = "sas")]
    SharedPrivateKey { device_id_pk: String },
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
    Tpm {
        registration_id: String,
    },
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub struct Provisioning {
    // This type used to have the `provisioning` field before the `dynamic_provisioning` field. It doesn't matter much except that the fields are
    // serialized in the order of definition when generating a new config via `aziot init`, and it would've been nice to serialize
    // the `provisioning` value before the `dynamic_reprovisioning` value.
    //
    // Unfortunately the TOML serializer needs "values" (like `dynamic_reprovisioning`) to come before "tables" (like `provisioning`),
    // otherwise it fails to serialize the value. It ought to not matter for this type because the `provisioning` value is flattened,
    // but the TOML serializer doesn't know this.
    //
    // So we have to move the `dynamic_provisioning` field before the `provisioning` field.
    #[serde(default)]
    pub dynamic_reprovisioning: bool,

    #[serde(flatten)]
    pub provisioning: ProvisioningType,
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

    /// Disables provisioning with IoT Hub for devices that use local identities only.
    None,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
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
    use super::{FromStr, Protocol};
    use crate::settings::{DpsAttestationMethod, ManualAuthMethod, ProvisioningType, Settings};
    use test_case::test_case;

    #[test]
    fn manual_sas_provisioning_settings_succeeds() {
        let s = Settings::new(std::path::Path::new("test/good_sas_config.toml")).unwrap();

        assert_eq!(s.provisioning.dynamic_reprovisioning, false);

        match s.provisioning.provisioning {
            ProvisioningType::Manual {
                iothub_hostname: _,
                device_id: _,
                authentication,
            } => match authentication {
                ManualAuthMethod::SharedPrivateKey { device_id_pk: _ } => {}
                _ => panic!("incorrect provisioning type selected"),
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
            } => match attestation {
                DpsAttestationMethod::SymmetricKey {
                    registration_id: _,
                    symmetric_key: _,
                } => (),
                _ => panic!("incorrect provisioning type selected"),
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

    #[test]
    fn bad_local_id_settings_fails() {
        assert!(
            Settings::new(std::path::Path::new("test/bad_local_config.toml")).is_err(),
            "bad_local_config.toml read should fail"
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
