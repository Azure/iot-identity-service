// Copyright (c) Microsoft. All rights reserved.

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DeviceId(pub String);
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct ModuleId(pub String);
#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct GenId(pub String);

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
#[serde(tag = "type", content = "spec")]
pub enum Identity {
    Aziot(AzureIoTSpec),
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct AzureIoTSpec {
    #[serde(rename = "hubName")]
    pub hub_name: String,
    #[serde(rename = "deviceId")]
    pub device_id: DeviceId,
    #[serde(rename = "moduleId", skip_serializing_if = "Option::is_none")]
    pub module_id: Option<ModuleId>,
    #[serde(rename = "genId", skip_serializing_if = "Option::is_none")]
    pub gen_id: Option<GenId>,
    #[serde(rename = "auth")]
    pub auth: AuthenticationInfo
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct AuthenticationInfo {
    #[serde(rename = "type")]
    pub auth_type: AuthenticationType,
    #[serde(rename = "keyHandle")]
    pub key_handle: aziot_key_common::KeyHandle,
    #[serde(rename = "certId", skip_serializing_if = "Option::is_none")]
    pub cert_id: Option<String>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthenticationType {
    SaS,
    X509,
}
