// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct DeviceRegistration {
    #[serde(rename = "registrationId", skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct DeviceRegistrationResult {
    /// Registration result returned when using X509 attestation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509: Option<X509RegistrationResult>,
    /// Registration result returned when using SymmetricKey attestation
    #[serde(rename = "symmetricKey", skip_serializing_if = "Option::is_none")]
    pub symmetric_key: Option<SymmetricKeyRegistrationResult>,
    /// The registration ID is alphanumeric, lowercase, and may contain hyphens.
    #[serde(rename = "registrationId", skip_serializing_if = "Option::is_none")]
    pub registration_id: Option<String>,
    /// Registration create date time (in UTC).
    #[serde(rename = "createdDateTimeUtc", skip_serializing_if = "Option::is_none")]
    pub created_date_time_utc: Option<String>,
    /// Assigned Azure IoT Hub.
    #[serde(rename = "assignedHub", skip_serializing_if = "Option::is_none")]
    pub assigned_hub: Option<String>,
    /// Device ID.
    #[serde(rename = "deviceId", skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Enrollment status.
    #[serde(rename = "status", skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Substatus for 'Assigned' devices. Possible values include -
    /// 'initialAssignment':  Device has been assigned to an IoT hub for the first time,
    /// 'deviceDataMigrated': Device has been assigned to a different IoT hub and its
    ///                       device data was migrated from the previously assigned IoT hub.
    ///                       Device data was removed from the previously assigned IoT hub,
    /// 'deviceDataReset':    Device has been assigned to a different IoT hub and its device
    ///                       data was populated from the initial state stored in the enrollment.
    ///                       Device data was removed from the previously assigned IoT hub.
    #[serde(rename = "substatus", skip_serializing_if = "Option::is_none")]
    pub substatus: Option<String>,
    /// Error code.
    #[serde(rename = "errorCode", skip_serializing_if = "Option::is_none")]
    pub error_code: Option<i32>,
    /// Error message.
    #[serde(rename = "errorMessage", skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    /// Last updated date time (in UTC).
    #[serde(
        rename = "lastUpdatedDateTimeUtc",
        skip_serializing_if = "Option::is_none"
    )]
    pub last_updated_date_time_utc: Option<String>,
    /// The entity tag associated with the resource.
    #[serde(rename = "etag", skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct SymmetricKeyRegistrationResult {
    #[serde(rename = "enrollmentGroupId")]
    pub enrollment_group_id: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct X509RegistrationResult {
    #[serde(rename = "certificateInfo", skip_serializing_if = "Option::is_none")]
    pub certificate_info: Option<X509CertificateInfo>,
    #[serde(rename = "enrollmentGroupId", skip_serializing_if = "Option::is_none")]
    pub enrollment_group_id: Option<String>,
    #[serde(
        rename = "signingCertificateInfo",
        skip_serializing_if = "Option::is_none"
    )]
    pub signing_certificate_info: Option<X509CertificateInfo>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct X509CertificateInfo {
    #[serde(rename = "subjectName")]
    pub subject_name: String,
    #[serde(rename = "sha1Thumbprint")]
    pub sha1_thumbprint: String,
    #[serde(rename = "sha256Thumbprint")]
    pub sha256_thumbprint: String,
    #[serde(rename = "issuerName")]
    pub issuer_name: String,
    #[serde(rename = "notBeforeUtc")]
    pub not_before_utc: String,
    #[serde(rename = "notAfterUtc")]
    pub not_after_utc: String,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    #[serde(rename = "version")]
    pub version: i32,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct RegistrationOperationStatus {
    /// Operation ID.
    #[serde(rename = "operationId")]
    pub operation_id: String,
    /// Device enrollment status.
    #[serde(rename = "status", skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Device registration status.
    #[serde(rename = "registrationState", skip_serializing_if = "Option::is_none")]
    pub registration_state: Option<DeviceRegistrationResult>,
}
