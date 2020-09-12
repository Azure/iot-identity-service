// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ApiVersion {
	V2020_09_01,
	Max,
}

impl std::fmt::Display for ApiVersion {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(match self {
			ApiVersion::V2020_09_01 => "2020-09-01",
			ApiVersion::Max => "MAX",
		})
	}
}

impl std::str::FromStr for ApiVersion {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		match s {
			"2020-09-01" => Ok(ApiVersion::V2020_09_01),
			_ => Err(()),
		}
	}
}

pub mod create_derived_key {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "baseKeyHandle")]
		pub base_handle: aziot_key_common::KeyHandle,

		#[serde(rename = "derivationData")]
		pub derivation_data: http_common::ByteString,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		#[serde(rename = "keyHandle")]
		pub handle: aziot_key_common::KeyHandle,
	}
}

pub mod create_key_if_not_exists {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "keyId")]
		pub id: String,

		#[serde(rename = "lengthBytes")]
		pub generate_key_len: Option<usize>,

		#[serde(rename = "keyBytes")]
		pub import_key_bytes: Option<http_common::ByteString>,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		#[serde(rename = "keyHandle")]
		pub handle: aziot_key_common::KeyHandle,
	}
}

pub mod create_key_pair_if_not_exists {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "keyId")]
		pub id: String,

		pub preferred_algorithms: Option<String>,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		#[serde(rename = "keyHandle")]
		pub handle: aziot_key_common::KeyHandle,
	}
}

pub mod decrypt {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "keyHandle")]
		pub key_handle: aziot_key_common::KeyHandle,

		#[serde(flatten)]
		pub parameters: crate::encrypt::Parameters,

		pub ciphertext: http_common::ByteString,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		pub plaintext: http_common::ByteString,
	}
}

pub mod encrypt {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "keyHandle")]
		pub key_handle: aziot_key_common::KeyHandle,

		#[serde(flatten)]
		pub parameters: Parameters,

		pub plaintext: http_common::ByteString,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	#[serde(tag = "algorithm", content = "parameters")]
	pub enum Parameters {
		#[serde(rename = "AEAD")]
		Aead {
			iv: http_common::ByteString,
			aad: http_common::ByteString,
		},

		#[serde(rename = "RSA-PKCS1")]
		RsaPkcs1,

		#[serde(rename = "RSA-NO-PADDING")]
		RsaNoPadding,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		pub ciphertext: http_common::ByteString,
	}
}

pub mod export_derived_key {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "keyHandle")]
		pub handle: aziot_key_common::KeyHandle,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		#[serde(rename = "key")]
		pub key: http_common::ByteString,
	}
}

pub mod get_key_pair_public_parameter {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "keyHandle")]
		pub key_handle: aziot_key_common::KeyHandle,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		pub value: String,
	}
}

pub mod load {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		#[serde(rename = "keyHandle")]
		pub handle: aziot_key_common::KeyHandle,
	}
}

pub mod sign {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "keyHandle")]
		pub key_handle: aziot_key_common::KeyHandle,

		#[serde(flatten)]
		pub parameters: Parameters,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	#[serde(tag = "algorithm", content = "parameters")]
	pub enum Parameters {
		#[serde(rename = "ECDSA")]
		Ecdsa {
			digest: http_common::ByteString,
		},

		#[serde(rename = "HMAC-SHA256")]
		HmacSha256 {
			message: http_common::ByteString,
		},
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		pub signature: http_common::ByteString,
	}
}
