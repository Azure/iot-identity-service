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
#[serde(rename = "cert_issuance")]
pub struct CertificateIssuance {
    #[serde(rename = "device-id")]
    pub device_identity: CertificateIssuanceType,

    #[serde(rename = "module-id")]
    pub module_identity: CertificateIssuanceType,

    #[serde(rename = "module-server")]
    pub module_server: CertificateIssuanceType,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CertificateIssuanceType {
    Dps,
    Est,
    Local,
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
    pub cert_issuance: CertificateIssuance,

    pub provisioning: Provisioning,
}

impl Settings {
    pub fn new(filename: &std::path::Path) -> Result<Self, Error> {
        let settings = std::fs::read_to_string(filename).map_err(|err| Error::LoadSettings(err))?;
        let settings = toml::from_str(&settings).map_err(|err| Error::ParseSettings(err))?;

        Ok(settings)
    }
}

#[cfg(test)]
mod tests {
    use super::CertificateIssuanceType;
    use crate::settings::{ProvisioningType, Settings};

    #[test]
    fn manual_sas_provisioning_settings_succeeds() {
        let s = Settings::new(std::path::Path::new("test/good_sas_config.toml")).unwrap();

        assert_eq!(
            s.cert_issuance.device_identity,
            CertificateIssuanceType::Dps
        );
        assert_eq!(
            s.cert_issuance.module_identity,
            CertificateIssuanceType::Dps
        );
        assert_eq!(s.cert_issuance.module_server, CertificateIssuanceType::Dps);
        assert_eq!(s.provisioning.dynamic_reprovisioning, false);

        match s.provisioning.provisioning {
            ProvisioningType::Manual { authentication: _ } => assert!(true),
            _ => assert!(false, "incorrect provisioning type selected"),
        };
    }

    #[test]
    fn manual_dps_provisioning_settings_succeeds() {
        let s = Settings::new(std::path::Path::new("test/good_dps_config.toml")).unwrap();

        assert_eq!(
            s.cert_issuance.device_identity,
            CertificateIssuanceType::Dps
        );
        assert_eq!(
            s.cert_issuance.module_identity,
            CertificateIssuanceType::Dps
        );
        assert_eq!(s.cert_issuance.module_server, CertificateIssuanceType::Dps);

        match s.provisioning.provisioning {
            ProvisioningType::Dps {
                global_endpoint: _,
                scope_id: _,
                attestation: _,
            } => assert!(true),
            _ => assert!(false, "incorrect provisioning type selected"),
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
