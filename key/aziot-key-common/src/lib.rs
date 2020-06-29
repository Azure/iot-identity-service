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


	// RSA keys

	RsaPkcs1 {
		message_digest: RsaPkcs1MessageDigest,
	},

	RsaPss {
		mask_generation_function: RsaPssMaskGenerationFunction,
		salt_len: usize,
	},


	// Symmetric keys

	HmacSha256,
}

#[derive(Clone, Copy, Debug)]
pub enum RsaPkcs1MessageDigest {
	Sha1,
	Sha224,
	Sha256,
	Sha384,
	Sha512,
}

#[derive(Clone, Copy, Debug)]
pub enum RsaPssMaskGenerationFunction {
	Sha1,
	Sha224,
	Sha256,
	Sha384,
	Sha512,
}

#[derive(Clone, Debug)]
pub enum EncryptMechanism {
	Aead {
		iv: Vec<u8>,
		aad: Vec<u8>,
	}
}
