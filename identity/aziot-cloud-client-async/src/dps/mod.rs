// Copyright (c) Microsoft. All rights reserved.

mod register;
pub use register::schema::{Certificate, Device, TrustBundle};
pub use register::Register;

mod issue_cert;
pub use issue_cert::IssueCert;

const API_VERSION: &str = "api-version=2021-11-01-preview";

const POLL_PERIOD: tokio::time::Duration = tokio::time::Duration::from_secs(5);

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ServiceError {
    #[serde(alias = "errorCode")]
    pub code: i32,
    #[serde(alias = "errorMessage")]
    pub message: String,
}

impl From<ServiceError> for std::io::Error {
    fn from(err: ServiceError) -> std::io::Error {
        // TODO: DPS needs to make a change to allow the client to distinguish
        // this error code from others. For now, distinguish based on error message.
        match err.message.as_str() {
            "Device sent CSR but it is not configured in the service." => {
                // This is a retryable error. The DPS client should resend the request
                // without the client certificate CSR.
                std::io::Error::new(std::io::ErrorKind::InvalidInput, err.message)
            }

            _ => std::io::Error::new(std::io::ErrorKind::Other, err.message),
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationStatus {
    pub operation_id: String,
}
