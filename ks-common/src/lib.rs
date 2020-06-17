#![deny(rust_2018_idioms, warnings)]
#![allow(
)]

pub trait KeysServiceInterface {
	type Error;

	fn create_key_pair_if_not_exists(
		&self,
		id: &str,
		preferred_algorithms: Option<&str>,
	) -> Result<KeyHandle, Self::Error>;

	fn load_key_pair(
		&self,
		id: &str,
	) -> Result<KeyHandle, Self::Error>;

	fn get_key_pair_public_parameter(
		&self,
		handle: &KeyHandle,
		parameter_name: &str,
	) -> Result<String, Self::Error>;

	fn create_key_if_not_exists(
		&self,
		id: &str,
		value: CreateKeyValue,
	) -> Result<KeyHandle, Self::Error>;

	fn sign(
		&self,
		handle: &KeyHandle,
		mechanism: SignMechanism,
		digest: &[u8],
	) -> Result<Vec<u8>, Self::Error>;

	fn encrypt(
		&self,
		handle: &KeyHandle,
		mechanism: EncryptMechanism,
		plaintext: &[u8],
	) -> Result<Vec<u8>, Self::Error>;

	fn decrypt(
		&self,
		handle: &KeyHandle,
		mechanism: EncryptMechanism,
		ciphertext: &[u8],
	) -> Result<Vec<u8>, Self::Error>;
}

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
