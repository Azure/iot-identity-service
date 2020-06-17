#![deny(rust_2018_idioms, warnings)]
#![allow(
	clippy::let_and_return,
)]

mod error;
pub use error::{Error, InternalError};

pub mod keygen;

pub struct Server {
	keygen: std::sync::Mutex<keygen::KeyGen>,
}

impl Server {
	pub fn new() -> Result<Self, Error> {
		let keygen = keygen::KeyGen::new()?;
		let keygen = std::sync::Mutex::new(keygen);

		Ok(Server {
			keygen,
		})
	}

	pub fn set_parameter(&mut self, name: &std::ffi::CStr, value: &std::ffi::CStr) -> Result<(), Error> {
		let mut keygen = self.keygen.lock().expect("keygen mutex poisoned");

		keygen.set_parameter(name, value)?;

		Ok(())
	}
}

impl ks_common::KeysServiceInterface for Server {
	type Error = Error;

	fn create_key_pair_if_not_exists(
		&self,
		id: &str,
		preferred_algorithms: Option<&str>,
	) -> Result<ks_common::KeyHandle, Self::Error> {
		let mut keygen = self.keygen.lock().expect("keygen mutex poisoned");
		let keygen = &mut *keygen;

		let id_cstr = std::ffi::CString::new(id.to_owned()).map_err(|err| Error::invalid_parameter("id", err))?;
		let preferred_algorithms =
			preferred_algorithms
			.map(|preferred_algorithms| std::ffi::CString::new(preferred_algorithms.to_owned()))
			.transpose()
			.map_err(|err| Error::invalid_parameter("preferred_algorithms", err))?;
		keygen.create_key_pair_if_not_exists(&id_cstr, preferred_algorithms.as_ref().map(AsRef::as_ref))?;

		let handle = key_id_to_handle(&KeyId::KeyPair(id.into()), keygen)?;
		Ok(handle)
	}

	fn load_key_pair(
		&self,
		id: &str,
	) -> Result<ks_common::KeyHandle, Self::Error> {
		let mut keygen = self.keygen.lock().expect("keygen mutex poisoned");
		let keygen = &mut *keygen;

		let id_cstr = std::ffi::CString::new(id.to_owned()).map_err(|err| Error::invalid_parameter("id", err))?;
		keygen.load_key_pair(&id_cstr)?;

		let handle = key_id_to_handle(&KeyId::KeyPair(id.into()), keygen)?;
		Ok(handle)
	}

	fn get_key_pair_public_parameter(
		&self,
		handle: &ks_common::KeyHandle,
		parameter_name: &str,
	) -> Result<String, Self::Error> {
		let mut keygen = self.keygen.lock().expect("keygen mutex poisoned");
		let keygen = &mut *keygen;

		let (_, id_cstr) = key_handle_to_id(handle, keygen)?;

		let parameter_value = keygen.get_key_pair_public_parameter(&id_cstr, parameter_name)?;
		Ok(parameter_value)
	}

	fn create_key_if_not_exists(
		&self,
		id: &str,
		value: ks_common::CreateKeyValue,
	) -> Result<ks_common::KeyHandle, Self::Error> {
		let mut keygen = self.keygen.lock().expect("keygen mutex poisoned");
		let keygen = &mut *keygen;

		let id_cstr = std::ffi::CString::new(id.to_owned()).map_err(|err| Error::invalid_parameter("id", err))?;

		match value {
			ks_common::CreateKeyValue::Generate { length } =>
				keygen.create_key_if_not_exists(&id_cstr, length)?,

			ks_common::CreateKeyValue::Import { bytes } =>
				keygen.import_key(&id_cstr, &bytes)?,
		}

		let handle = key_id_to_handle(&KeyId::Key(id.into()), keygen)?;
		Ok(handle)
	}

	fn sign(
		&self,
		handle: &ks_common::KeyHandle,
		mechanism: ks_common::SignMechanism,
		digest: &[u8],
	) -> Result<Vec<u8>, Self::Error> {
		let mut keygen = self.keygen.lock().expect("keygen mutex poisoned");
		let keygen = &mut *keygen;

		let (id, id_cstr) = key_handle_to_id(handle, keygen)?;

		let signature = match (id, mechanism) {
			(KeyId::KeyPair(_), ks_common::SignMechanism::Ecdsa) =>
				keygen.sign(&id_cstr, keygen::sys::KEYGEN_SIGN_MECHANISM_ECDSA, std::ptr::null(), digest)?,

			(KeyId::KeyPair(_), ks_common::SignMechanism::RsaPkcs1 { message_digest }) => {
				let message_digest = match message_digest {
					ks_common::RsaPkcs1MessageDigest::Sha1 => keygen::sys::KEYGEN_RSA_PKCS1_MESSAGE_DIGEST_SHA1,
					ks_common::RsaPkcs1MessageDigest::Sha224 => keygen::sys::KEYGEN_RSA_PKCS1_MESSAGE_DIGEST_SHA224,
					ks_common::RsaPkcs1MessageDigest::Sha256 => keygen::sys::KEYGEN_RSA_PKCS1_MESSAGE_DIGEST_SHA256,
					ks_common::RsaPkcs1MessageDigest::Sha384 => keygen::sys::KEYGEN_RSA_PKCS1_MESSAGE_DIGEST_SHA384,
					ks_common::RsaPkcs1MessageDigest::Sha512 => keygen::sys::KEYGEN_RSA_PKCS1_MESSAGE_DIGEST_SHA512,
				};

				keygen.sign(
					&id_cstr,
					keygen::sys::KEYGEN_SIGN_MECHANISM_RSA_PKCS1,
					&message_digest as *const _ as *const std::ffi::c_void,
					digest,
				)?
			},

			(KeyId::KeyPair(_), ks_common::SignMechanism::RsaPss { mask_generation_function, salt_len }) => {
				/*
				let salt_len = std::convert::TryInto::try_into(salt_len).map_err(|err| Error::invalid_parameter("mechanism.salt_len", err))?;

				let parameters = keygen::sys::KEYGEN_SIGN_RSA_PSS_PARAMETERS {
					mask_generation_function: match mask_generation_function {
						ks_common::RsaPssMaskGenerationFunction::Sha1 => keygen::sys::KEYGEN_SIGN_RSA_PSS_MASK_GENERATION_FUNCTION_SHA1,
						ks_common::RsaPssMaskGenerationFunction::Sha224 => keygen::sys::KEYGEN_SIGN_RSA_PSS_MASK_GENERATION_FUNCTION_SHA224,
						ks_common::RsaPssMaskGenerationFunction::Sha256 => keygen::sys::KEYGEN_SIGN_RSA_PSS_MASK_GENERATION_FUNCTION_SHA256,
						ks_common::RsaPssMaskGenerationFunction::Sha384 => keygen::sys::KEYGEN_SIGN_RSA_PSS_MASK_GENERATION_FUNCTION_SHA384,
						ks_common::RsaPssMaskGenerationFunction::Sha512 => keygen::sys::KEYGEN_SIGN_RSA_PSS_MASK_GENERATION_FUNCTION_SHA512,
					},

					salt_len,
				};

				keygen.sign(&id_cstr, keygen::sys::KEYGEN_SIGN_MECHANISM_RSA_PSS, message_digest, &parameters as *const _ as _, digest).map_err(Error::Sign)?
				*/

				unimplemented!("sign(RSA_PSS, {:?}, {})", mask_generation_function, salt_len);
			},

			(KeyId::Key(_), ks_common::SignMechanism::HmacSha256) =>
				keygen.sign(
					&id_cstr,
					keygen::sys::KEYGEN_SIGN_MECHANISM_HMAC_SHA256,
					std::ptr::null(),
					digest,
				)?,

			_ => return Err(Error::invalid_parameter("mechanism", "mechanism cannot be used with this key type")),
		};

		Ok(signature)
	}

	fn encrypt(
		&self,
		handle: &ks_common::KeyHandle,
		mechanism: ks_common::EncryptMechanism,
		plaintext: &[u8],
	) -> Result<Vec<u8>, Self::Error> {
		let mut keygen = self.keygen.lock().expect("keygen mutex poisoned");
		let keygen = &mut *keygen;

		let (id, id_cstr) = key_handle_to_id(handle, keygen)?;

		let ciphertext = match (id, mechanism) {
			(KeyId::Key(_), ks_common::EncryptMechanism::Aead { iv, aad }) => {
				let parameters = keygen::sys::KEYGEN_ENCRYPT_AEAD_PARAMETERS {
					iv: iv.as_ptr(),
					iv_len: iv.len(),
					aad: aad.as_ptr(),
					aad_len: aad.len(),
				};

				keygen.encrypt(
					&id_cstr,
					keygen::sys::KEYGEN_ENCRYPT_MECHANISM_AEAD,
					&parameters as *const _ as *const std::ffi::c_void,
					plaintext,
				)?
			},

			_ => return Err(Error::invalid_parameter("mechanism", "mechanism cannot be used with this key type")),
		};

		Ok(ciphertext)
	}

	fn decrypt(
		&self,
		handle: &ks_common::KeyHandle,
		mechanism: ks_common::EncryptMechanism,
		ciphertext: &[u8],
	) -> Result<Vec<u8>, Self::Error> {
		let mut keygen = self.keygen.lock().expect("keygen mutex poisoned");
		let keygen = &mut *keygen;

		let (id, id_cstr) = key_handle_to_id(handle, keygen)?;

		let plaintext = match (id, mechanism) {
			(KeyId::Key(_), ks_common::EncryptMechanism::Aead { iv, aad }) => {
				let parameters = keygen::sys::KEYGEN_ENCRYPT_AEAD_PARAMETERS {
					iv: iv.as_ptr(),
					iv_len: iv.len(),
					aad: aad.as_ptr(),
					aad_len: aad.len(),
				};

				keygen.decrypt(
					&id_cstr,
					keygen::sys::KEYGEN_ENCRYPT_MECHANISM_AEAD,
					&parameters as *const _ as *const std::ffi::c_void,
					ciphertext,
				)?
			},

			_ => return Err(Error::invalid_parameter("mechanism", "mechanism cannot be used with this key type")),
		};

		Ok(plaintext)
	}
}

/// Decoded from a ks_common::KeyHandle
#[derive(Debug, serde::Deserialize, serde::Serialize)]
enum KeyId<'a> {
	KeyPair(std::borrow::Cow<'a, str>),
	Key(std::borrow::Cow<'a, str>),
}

impl KeyId<'_> {
	fn borrow(&self) -> KeyId<'_> {
		match self {
			KeyId::KeyPair(id) => KeyId::KeyPair(std::borrow::Cow::Borrowed(&*id)),
			KeyId::Key(id) => KeyId::Key(std::borrow::Cow::Borrowed(&*id)),
		}
	}
}

fn master_encryption_key_id() -> &'static std::ffi::CStr {
	const MASTER_ENCRYPTION_KEY_ID_C: &[u8] = b"master-encryption-key\0";
	std::ffi::CStr::from_bytes_with_nul(MASTER_ENCRYPTION_KEY_ID_C).expect("hard-coded key ID is valid CStr")
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct Sr<'a> {
	key_id: KeyId<'a>,
	nonce: String,
}

fn key_handle_to_id(handle: &ks_common::KeyHandle, keygen: &mut keygen::KeyGen) -> Result<(KeyId<'static>, std::ffi::CString), Error> {
	// DEVNOTE:
	//
	// Map errors from using the master encryption key to Error::Internal instead of relying on `?`,
	// because all errors from using the master encryption key are internal errors.

	let params = handle.0.split('&');

	let mut sr = None;
	let mut sig = None;

	for param in params {
		if param.starts_with("sr=") {
			let value = &param["sr=".len()..];
			let value = base64::decode(value.as_bytes()).map_err(|_| Error::invalid_parameter("handle", "invalid handle"))?;
			let value = String::from_utf8(value).map_err(|_| Error::invalid_parameter("handle", "invalid handle"))?;
			sr = Some(value);
		}
		else if param.starts_with("sig=") {
			let value = &param["sig=".len()..];
			let value = base64::decode(value.as_bytes()).map_err(|_| Error::invalid_parameter("handle", "invalid handle"))?;
			sig = Some(value);
		}
	}

	let sr = sr.ok_or_else(|| Error::invalid_parameter("handle", "invalid handle"))?;
	let sig = sig.ok_or_else(|| Error::invalid_parameter("handle", "invalid handle"))?;

	let master_encryption_key_id = master_encryption_key_id();
	keygen.create_key_if_not_exists(master_encryption_key_id, 32).map_err(|err| Error::Internal(InternalError::CreateKeyIfNotExistsGenerate(err)))?;
	let ok =
		keygen.verify(
			master_encryption_key_id,
			keygen::sys::KEYGEN_SIGN_MECHANISM_HMAC_SHA256,
			std::ptr::null(),
			sr.as_bytes(),
			&sig,
		).map_err(|err| Error::Internal(InternalError::Verify(err)))?;
	if !ok {
		return Err(Error::invalid_parameter("handle", "invalid handle"));
	}

	let sr: Sr<'static> = serde_json::from_str(&sr).map_err(|_| Error::invalid_parameter("handle", "invalid handle"))?;

	let id = sr.key_id;

	let id_cstr = match &id {
		KeyId::KeyPair(id) => {
			let id_cstr = std::ffi::CString::new(id.clone().into_owned()).map_err(|err| Error::invalid_parameter("handle", err))?;
			id_cstr
		},

		KeyId::Key(id) => {
			let id_cstr = std::ffi::CString::new(id.clone().into_owned()).map_err(|err| Error::invalid_parameter("handle", err))?;
			id_cstr
		},
	};

	Ok((id, id_cstr))
}

fn key_id_to_handle(id: &KeyId<'_>, keygen: &mut keygen::KeyGen) -> Result<ks_common::KeyHandle, Error> {
	let sr = {
		let mut nonce = [0_u8; 64];
		openssl::rand::rand_bytes(&mut nonce).map_err(|err| Error::Internal(InternalError::GenerateNonce(err)))?;
		let nonce = base64::encode(&nonce[..]);

		let sr = Sr {
			key_id: id.borrow(),
			nonce,
		};
		let sr = serde_json::to_string(&sr).expect("cannot fail to convert Sr to JSON");
		sr
	};

	let master_encryption_key_id = master_encryption_key_id();
	keygen.create_key_if_not_exists(master_encryption_key_id, 32).map_err(|err| Error::Internal(InternalError::CreateKeyIfNotExistsGenerate(err)))?;
	let sig =
		keygen.sign(
			master_encryption_key_id,
			keygen::sys::KEYGEN_SIGN_MECHANISM_HMAC_SHA256,
			std::ptr::null(),
			sr.as_bytes(),
		).map_err(|err| Error::Internal(InternalError::Sign(err)))?;

	// TODO: se for expiry

	// This *could* use percent-encoding instead of string concat. However, the only potential problem with base64-encoded values can arise from a trailing =,
	// since = is also used between a key and its value. But that usage of = is not ambiguous, so it isn't a problem.
	let token = format!("sr={}&sig={}", base64::encode(sr.as_bytes()), base64::encode(&sig));

	let handle = ks_common::KeyHandle(token);
	Ok(handle)
}
