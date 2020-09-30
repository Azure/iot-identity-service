// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct DeviceId(pub String);
#[derive(Clone, Debug, Eq, Ord, PartialOrd, PartialEq, serde::Deserialize, serde::Serialize)]
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
	#[serde(rename = "auth", skip_serializing_if = "Option::is_none")]
	pub auth: Option<AuthenticationInfo>,
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

pub struct Uid(u32);

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IdType {
	Device,
	Local,
	Module,
}

#[derive(Clone)]
pub struct IoTHubDevice {
	pub iothub_hostname: String,

	pub device_id: String,

	pub credentials: Credentials,
}

#[derive(Clone)]
pub enum Credentials {
	SharedPrivateKey (String),

	X509 {
		identity_cert: String,
		identity_pk: String,
	},
}

impl From<Credentials> for AuthenticationInfo {
	fn from(c: Credentials) -> Self {
		match c {
			Credentials::SharedPrivateKey(k) => AuthenticationInfo {
				auth_type: AuthenticationType::SaS,
				key_handle: aziot_key_common::KeyHandle(k),
				cert_id: None,
			},
			Credentials::X509 { identity_cert, identity_pk } => AuthenticationInfo {
				auth_type: AuthenticationType::X509,
				key_handle: aziot_key_common::KeyHandle(identity_pk),
				cert_id: Some(identity_cert),
			},
		}
	}
}

pub mod hub {
	#[derive(Clone, Copy, Debug, serde::Deserialize, PartialEq, serde::Serialize)]
	#[serde(rename_all = "camelCase")]
	pub enum AuthType {
		None,
		Sas,
		X509,

	}
	#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
	#[serde(rename_all = "camelCase")]
	pub struct X509Thumbprint {
		#[serde(skip_serializing_if = "Option::is_none")]
		pub primary_thumbprint: Option<String>,
		#[serde(skip_serializing_if = "Option::is_none")]
		pub secondary_thumbprint: Option<String>,
	}

	#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
	#[serde(rename_all = "camelCase")]
	pub struct SymmetricKey {
		#[serde(skip_serializing_if = "Option::is_none")]
		pub primary_key: Option<http_common::ByteString>,
		#[serde(skip_serializing_if = "Option::is_none")]
		pub secondary_key: Option<http_common::ByteString>,
	}

	#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
	#[serde(rename_all = "camelCase")]
	pub struct AuthMechanism {
		#[serde(skip_serializing_if = "Option::is_none")]
		pub symmetric_key: Option<SymmetricKey>,

		#[serde(skip_serializing_if = "Option::is_none")]
		pub x509_thumbprint: Option<X509Thumbprint>,

		#[serde(skip_serializing_if = "Option::is_none")]
		pub type_: Option<AuthType>,
	}

	#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
	#[serde(rename_all = "camelCase")]
	pub struct Module {
		pub module_id: String,
		#[serde(skip_serializing_if = "Option::is_none")]
		pub managed_by: Option<String>,

		pub device_id: String,
		#[serde(skip_serializing_if = "Option::is_none")]
		pub generation_id: Option<String>,
		#[serde(skip_serializing_if = "Option::is_none")]
		pub authentication: Option<AuthMechanism>,
	}
}
