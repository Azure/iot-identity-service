// Copyright (c) Microsoft. All rights reserved.

pub mod request {
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct DeviceRegistration {
        pub registration_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub payload: Option<serde_json::Value>,
    }

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TpmRegistration {
        pub registration_id: String,
        pub tpm: Option<super::TpmAttestation>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub payload: Option<serde_json::Value>,
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
        let engine = base64::engine::general_purpose::STANDARD;

        TpmAttestation {
            endorsement_key: base64::Engine::encode(&engine, keys.endorsement_key),
            storage_root_key: base64::Engine::encode(&engine, keys.storage_root_key),
        }
    }
}

pub mod response {
    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ServiceError {
        #[serde(alias = "errorCode")]
        pub code: i32,
        #[serde(alias = "errorMessage")]
        pub message: String,
    }

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TpmAuthKey {
        pub authentication_key: String,
    }

    #[derive(Debug, serde::Deserialize, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct OperationStatus {
        pub operation_id: String,
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

            tpm: Option<TpmAuthKey>,
        },
        Assigning {
            #[serde(rename = "registrationId")]
            registration_id: String,
        },
        Failed(ServiceError),
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub assigned_hub: String,
    pub device_id: String,
    pub payload: Option<serde_json::Value>,
}

impl From<response::ServiceError> for std::io::Error {
    fn from(err: response::ServiceError) -> std::io::Error {
        std::io::Error::other(err.message)
    }
}
