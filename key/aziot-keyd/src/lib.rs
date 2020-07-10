#![deny(rust_2018_idioms, warnings)]
#![allow(
	clippy::let_and_return,
)]

mod error;
pub use error::{Error, InternalError};

pub mod keys;

pub struct Server {
	keys: std::sync::Mutex<keys::Keys>,
}

impl Server {
	pub fn new() -> Result<Self, Error> {
		let keys = keys::Keys::new()?;
		let keys = std::sync::Mutex::new(keys);

		Ok(Server {
			keys,
		})
	}

	pub fn set_parameter(&mut self, name: &std::ffi::CStr, value: &std::ffi::CStr) -> Result<(), Error> {
		let mut keys = self.keys.lock().expect("keys mutex poisoned");

		keys.set_parameter(name, value)?;

		Ok(())
	}

	pub fn create_key_pair_if_not_exists(
		&self,
		id: &str,
		preferred_algorithms: Option<&str>,
	) -> Result<aziot_key_common::KeyHandle, Error> {
		let mut keys = self.keys.lock().expect("keys mutex poisoned");
		let keys = &mut *keys;

		let id_cstr = std::ffi::CString::new(id.to_owned()).map_err(|err| Error::invalid_parameter("id", err))?;
		let preferred_algorithms =
			preferred_algorithms
			.map(|preferred_algorithms| std::ffi::CString::new(preferred_algorithms.to_owned()))
			.transpose()
			.map_err(|err| Error::invalid_parameter("preferred_algorithms", err))?;
		keys.create_key_pair_if_not_exists(&id_cstr, preferred_algorithms.as_ref().map(AsRef::as_ref))?;

		let handle = key_id_to_handle(&KeyId::KeyPair(id.into()), keys)?;
		Ok(handle)
	}

	pub fn load_key_pair(
		&self,
		id: &str,
	) -> Result<aziot_key_common::KeyHandle, Error> {
		let mut keys = self.keys.lock().expect("keys mutex poisoned");
		let keys = &mut *keys;

		let id_cstr = std::ffi::CString::new(id.to_owned()).map_err(|err| Error::invalid_parameter("id", err))?;
		keys.load_key_pair(&id_cstr)?;

		let handle = key_id_to_handle(&KeyId::KeyPair(id.into()), keys)?;
		Ok(handle)
	}

	pub fn get_key_pair_public_parameter(
		&self,
		handle: &aziot_key_common::KeyHandle,
		parameter_name: &str,
	) -> Result<String, Error> {
		let mut keys = self.keys.lock().expect("keys mutex poisoned");
		let keys = &mut *keys;

		let (_, id_cstr) = key_handle_to_id(handle, keys)?;

		let parameter_value = keys.get_key_pair_public_parameter(&id_cstr, parameter_name)?;
		Ok(parameter_value)
	}

	pub fn create_key_if_not_exists(
		&self,
		id: &str,
		value: aziot_key_common::CreateKeyValue,
	) -> Result<aziot_key_common::KeyHandle, Error> {
		let mut keys = self.keys.lock().expect("keys mutex poisoned");
		let keys = &mut *keys;

		let id_cstr = std::ffi::CString::new(id.to_owned()).map_err(|err| Error::invalid_parameter("id", err))?;

		match value {
			aziot_key_common::CreateKeyValue::Generate { length } =>
				keys.create_key_if_not_exists(&id_cstr, length)?,

			aziot_key_common::CreateKeyValue::Import { bytes } =>
				keys.import_key(&id_cstr, &bytes)?,
		}

		let handle = key_id_to_handle(&KeyId::Key(id.into()), keys)?;
		Ok(handle)
	}

	pub fn sign(
		&self,
		handle: &aziot_key_common::KeyHandle,
		mechanism: aziot_key_common::SignMechanism,
		digest: &[u8],
	) -> Result<Vec<u8>, Error> {
		let mut keys = self.keys.lock().expect("keys mutex poisoned");
		let keys = &mut *keys;

		let (id, id_cstr) = key_handle_to_id(handle, keys)?;

		let signature = match (id, mechanism) {
			(KeyId::KeyPair(_), aziot_key_common::SignMechanism::Ecdsa) =>
				keys.sign(&id_cstr, keys::sys::KEYGEN_SIGN_MECHANISM_ECDSA, std::ptr::null(), digest)?,

			(KeyId::Key(_), aziot_key_common::SignMechanism::HmacSha256) =>
				keys.sign(
					&id_cstr,
					keys::sys::KEYGEN_SIGN_MECHANISM_HMAC_SHA256,
					std::ptr::null(),
					digest,
				)?,

			_ => return Err(Error::invalid_parameter("mechanism", "mechanism cannot be used with this key type")),
		};

		Ok(signature)
	}

	pub fn encrypt(
		&self,
		handle: &aziot_key_common::KeyHandle,
		mechanism: aziot_key_common::EncryptMechanism,
		plaintext: &[u8],
	) -> Result<Vec<u8>, Error> {
		let mut keys = self.keys.lock().expect("keys mutex poisoned");
		let keys = &mut *keys;

		let (id, id_cstr) = key_handle_to_id(handle, keys)?;

		let ciphertext = match (id, mechanism) {
			(KeyId::Key(_), aziot_key_common::EncryptMechanism::Aead { iv, aad }) => {
				let parameters = keys::sys::KEYGEN_ENCRYPT_AEAD_PARAMETERS {
					iv: iv.as_ptr(),
					iv_len: iv.len(),
					aad: aad.as_ptr(),
					aad_len: aad.len(),
				};

				keys.encrypt(
					&id_cstr,
					keys::sys::KEYGEN_ENCRYPT_MECHANISM_AEAD,
					&parameters as *const _ as *const std::ffi::c_void,
					plaintext,
				)?
			},

			(KeyId::KeyPair(_), aziot_key_common::EncryptMechanism::RsaPkcs1) => {
				keys.encrypt(
					&id_cstr,
					keys::sys::KEYGEN_ENCRYPT_MECHANISM_RSA_PKCS1,
					std::ptr::null_mut(),
					plaintext,
				)?
			},

			_ => return Err(Error::invalid_parameter("mechanism", "mechanism cannot be used with this key type")),
		};

		Ok(ciphertext)
	}

	pub fn decrypt(
		&self,
		handle: &aziot_key_common::KeyHandle,
		mechanism: aziot_key_common::EncryptMechanism,
		ciphertext: &[u8],
	) -> Result<Vec<u8>, Error> {
		let mut keys = self.keys.lock().expect("keys mutex poisoned");
		let keys = &mut *keys;

		let (id, id_cstr) = key_handle_to_id(handle, keys)?;

		let plaintext = match (id, mechanism) {
			(KeyId::Key(_), aziot_key_common::EncryptMechanism::Aead { iv, aad }) => {
				let parameters = keys::sys::KEYGEN_ENCRYPT_AEAD_PARAMETERS {
					iv: iv.as_ptr(),
					iv_len: iv.len(),
					aad: aad.as_ptr(),
					aad_len: aad.len(),
				};

				keys.decrypt(
					&id_cstr,
					keys::sys::KEYGEN_ENCRYPT_MECHANISM_AEAD,
					&parameters as *const _ as *const std::ffi::c_void,
					ciphertext,
				)?
			},

			_ => return Err(Error::invalid_parameter("mechanism", "mechanism cannot be used with this key type")),
		};

		Ok(plaintext)
	}
}

/// Decoded from a aziot_key_common::KeyHandle
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

fn key_handle_to_id(handle: &aziot_key_common::KeyHandle, keys: &mut keys::Keys) -> Result<(KeyId<'static>, std::ffi::CString), Error> {
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
	keys.create_key_if_not_exists(master_encryption_key_id, 32).map_err(|err| Error::Internal(InternalError::CreateKeyIfNotExistsGenerate(err)))?;
	let ok =
		keys.verify(
			master_encryption_key_id,
			keys::sys::KEYGEN_SIGN_MECHANISM_HMAC_SHA256,
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

fn key_id_to_handle(id: &KeyId<'_>, keys: &mut keys::Keys) -> Result<aziot_key_common::KeyHandle, Error> {
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
	keys.create_key_if_not_exists(master_encryption_key_id, 32).map_err(|err| Error::Internal(InternalError::CreateKeyIfNotExistsGenerate(err)))?;
	let sig =
		keys.sign(
			master_encryption_key_id,
			keys::sys::KEYGEN_SIGN_MECHANISM_HMAC_SHA256,
			std::ptr::null(),
			sr.as_bytes(),
		).map_err(|err| Error::Internal(InternalError::Sign(err)))?;

	// TODO: se for expiry

	// This *could* use percent-encoding instead of string concat. However, the only potential problem with base64-encoded values can arise from a trailing =,
	// since = is also used between a key and its value. But that usage of = is not ambiguous, so it isn't a problem.
	let token = format!("sr={}&sig={}", base64::encode(sr.as_bytes()), base64::encode(&sig));

	let handle = aziot_key_common::KeyHandle(token);
	Ok(handle)
}
