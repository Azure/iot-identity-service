// Copyright (c) Microsoft. All rights reserved.

pub mod request {
    #[derive(Debug, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct DeviceRegistration {
        pub registration_id: String,
    }

    #[derive(Debug, serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TpmRegistration {
        pub registration_id: String,
        pub tpm: Option<super::TpmAttestation>,
    }
}

#[derive(Debug, serde::Serialize)]
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
    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct ServiceError {
        #[serde(alias = "code")]
        pub error_code: i32,
        pub message: String,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct TpmAuthKey {
        pub authentication_key: String,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct OperationStatus {
        pub operation_id: String,
        pub status: super::EnrollmentStatus,
    }

    #[derive(Debug, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct DeviceRegistration {
        #[serde(flatten)]
        pub operation: OperationStatus,

        pub registration_state: super::RegistrationState,
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnrollmentStatus {
    Assigned,
    Assigning,
    Disabled,
    Failed,
    Unassigned,
}

#[derive(Debug, serde::Deserialize)]
#[serde(
    tag = "status",
    content = "registrationState",
    rename_all = "lowercase"
)]
pub enum RegistrationState {
    Assigning,
    Assigned(Device),
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub assigned_hub: String,
    pub device_id: String,
}
