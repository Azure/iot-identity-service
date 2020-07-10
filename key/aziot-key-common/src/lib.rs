#![deny(rust_2018_idioms, warnings)]
#![allow(
)]

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct KeyHandle(pub String);

#[derive(Clone, Debug)]
pub enum CreateKeyValue {
	Generate { length: usize },
	Import { bytes: Vec<u8> },
}

#[derive(Clone, Copy, Debug)]
pub enum SignMechanism {
	// ECDSA keys

	Ecdsa,


	// Symmetric keys

	HmacSha256,
}

#[derive(Clone, Debug)]
pub enum EncryptMechanism {
	Aead {
		iv: Vec<u8>,
		aad: Vec<u8>,
	},

	RsaPkcs1,
}
