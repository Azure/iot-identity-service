// Copyright (c) Microsoft. All rights reserved.

// use config::{Config, File, FileFormat};
use crate::error::Error;

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "method")]
#[serde(rename_all = "lowercase")]
pub enum ManualAuthMethod {
    #[serde(rename = "sas")]
    SharedPrivateKey {
        iothub_hostname: String,
        device_id: String,
        device_id_pk: String,
    },
    X509 {
        iothub_hostname: String,
        device_id: String,
        identity_cert: url::Url,
        identity_pk: url::Url,
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
        identity_cert: url::Url,
        identity_pk: url::Url,
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
        authentication: ManualAuthMethod,
    },
    Dps {
        global_endpoint: url::Url,
        scope_id: String,
        attestation: DpsAttestationMethod,
    },
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Settings {
    pub provisioning: Provisioning,
}

impl Settings {
    pub fn new(filename: &std::path::Path) -> Result<Self, Error> {
        let settings = std::fs::read_to_string(filename).map_err(Error::LoadSettings)?;
        let settings = toml::from_str(&settings).map_err(Error::ParseSettings)?;

        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use crate::settings::{ProvisioningType, Settings, DpsAttestationMethod, ManualAuthMethod};

    #[test]
    fn manual_sas_provisioning_settings_succeeds() {
        let s = Settings::new(std::path::Path::new("test/good_sas_config.toml")).unwrap();

        assert_eq!(s.provisioning.dynamic_reprovisioning, false);

        match s.provisioning.provisioning {
            ProvisioningType::Manual { authentication } => {
                match authentication {
                    ManualAuthMethod::SharedPrivateKey { 
                        iothub_hostname: _, 
                        device_id: _, 
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
}
