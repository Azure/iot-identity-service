// Copyright (c) Microsoft. All rights reserved.

pub mod request {
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct DeviceRegistration {
        pub registration_id: String,

        #[serde(
            rename = "clientCertificateCsr",
            skip_serializing_if = "Option::is_none"
        )]
        pub client_cert_csr: Option<String>,
    }

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TpmRegistration {
        pub registration_id: String,
        pub tpm: super::TpmAttestation,
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpmAttestation {
    pub endorsement_key: String,
    pub storage_root_key: String,
}

impl std::convert::From<aziot_tpm_common::TpmKeys> for TpmAttestation {
    fn from(keys: aziot_tpm_common::TpmKeys) -> TpmAttestation {
        TpmAttestation {
            endorsement_key: base64::encode(keys.endorsement_key),
            storage_root_key: base64::encode(keys.storage_root_key),
        }
    }
}

pub mod response {
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TpmAuthKey {
        pub authentication_key: String,
    }

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(
        tag = "status",
        content = "registrationState",
        rename_all = "lowercase"
    )]
    pub enum DeviceRegistration {
        Assigned {
            #[serde(flatten)]
            device: super::Device,

            #[serde(skip_serializing_if = "Option::is_none")]
            tpm: Option<TpmAuthKey>,
        },
        Assigning {
            #[serde(rename = "registrationId")]
            registration_id: String,
        },
        Failed(crate::dps::ServiceError),
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub assigned_hub: String,
    pub device_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_bundle: Option<TrustBundle>,

    #[serde(
        rename = "issuedClientCertificate",
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_cert: Option<String>,

    #[serde(
        rename = "deviceCertificateIssuanceSettings",
        skip_serializing_if = "Option::is_none"
    )]
    pub cert_policy: Option<aziot_identity_common::CertPolicy>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct TrustBundle {
    pub certificates: Vec<Certificate>,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct Certificate {
    pub certificate: String,
}
