#![deny(rust_2018_idioms, warnings)]
#![allow(
)]

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Error {
	pub message: std::borrow::Cow<'static, str>,
}

pub mod create_key_if_not_exists {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "keyId")]
		pub id: String,

		#[serde(rename = "lengthBytes")]
		pub generate_key_len: Option<usize>,

		#[serde(rename = "keyBytes")]
		pub import_key_bytes: Option<String>,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		#[serde(rename = "keysServiceHandle")]
		pub handle: ks_common::KeyHandle,
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
		#[serde(rename = "keysServiceHandle")]
		pub handle: ks_common::KeyHandle,
	}
}

pub mod decrypt {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "keysServiceHandle")]
		pub key_handle: ks_common::KeyHandle,

		#[serde(flatten)]
		pub parameters: Parameters,

		pub ciphertext: String,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	#[serde(tag = "algorithm", content = "parameters")]
	pub enum Parameters {
		#[serde(rename = "AEAD")]
		Aead {
			iv: String,
			aad: String,
		},
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		pub plaintext: String,
	}
}

pub mod encrypt {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "keysServiceHandle")]
		pub key_handle: ks_common::KeyHandle,

		#[serde(flatten)]
		pub parameters: Parameters,

		pub plaintext: String,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	#[serde(tag = "algorithm", content = "parameters")]
	pub enum Parameters {
		#[serde(rename = "AEAD")]
		Aead {
			iv: String,
			aad: String,
		},
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		pub ciphertext: String,
	}
}

pub mod get_key_pair_public_parameter {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "keysServiceHandle")]
		pub key_handle: ks_common::KeyHandle,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		pub value: String,
	}
}

pub mod load_key_pair {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		#[serde(rename = "keysServiceHandle")]
		pub handle: ks_common::KeyHandle,
	}
}

pub mod sign {
	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Request {
		#[serde(rename = "keysServiceHandle")]
		pub key_handle: ks_common::KeyHandle,

		#[serde(flatten)]
		pub parameters: Parameters,
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	#[serde(tag = "algorithm", content = "parameters")]
	pub enum Parameters {
		#[serde(rename = "ECDSA")]
		Ecdsa {
			digest: String,
		},

		#[serde(rename = "RSA_PKCS1")]
		RsaPkcs1 {
			#[serde(rename = "messageDigestAlgorithm")]
			message_digest_algorithm: String,

			#[serde(rename = "message")]
			message: String,
		},

		#[serde(rename = "HMAC-SHA256")]
		HmacSha256 {
			message: String,
		},
	}

	#[derive(Debug, serde::Deserialize, serde::Serialize)]
	pub struct Response {
		pub signature: String,
	}
}
