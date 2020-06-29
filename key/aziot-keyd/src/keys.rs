#[derive(Clone, Copy, Debug)]
pub struct KeysRawError(pub(crate) sys::KEYGEN_ERROR);

impl std::fmt::Display for KeysRawError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self.0 {
			sys::KEYGEN_ERROR_FATAL => f.write_str("KEYGEN_ERROR_FATAL"),
			sys::KEYGEN_ERROR_INVALID_PARAMETER => f.write_str("KEYGEN_ERROR_INVALID_PARAMETER"),
			sys::KEYGEN_ERROR_EXTERNAL => f.write_str("KEYGEN_ERROR_EXTERNAL"),
			err => write!(f, "0x{:08x}", err),
		}
	}
}

#[derive(Debug)]
pub(crate) enum Keys {
	V2_0_0_0 {
		set_parameter: unsafe extern "C" fn(
			name: *const std::os::raw::c_char,
			value: *const std::os::raw::c_char,
		) -> sys::KEYGEN_ERROR,

		create_key_pair_if_not_exists: unsafe extern "C" fn(
			id: *const std::os::raw::c_char,
			preferred_algorithms: *const std::os::raw::c_char,
		) -> sys::KEYGEN_ERROR,

		load_key_pair: unsafe extern "C" fn(
			id: *const std::os::raw::c_char,
		) -> sys::KEYGEN_ERROR,

		get_key_pair_parameter: unsafe extern "C" fn(
			id: *const std::os::raw::c_char,
			r#type: sys::KEYGEN_KEY_PAIR_PARAMETER_TYPE,
			value: *mut std::os::raw::c_uchar,
			value_len: *mut usize,
		) -> sys::KEYGEN_ERROR,

		create_key_if_not_exists: unsafe extern "C" fn(
			id: *const std::os::raw::c_char,
			length: usize,
		) -> sys::KEYGEN_ERROR,

		import_key: unsafe extern "C" fn(
			id: *const std::os::raw::c_char,
			bytes: *const u8,
			bytes_length: usize,
		) -> sys::KEYGEN_ERROR,

		sign: unsafe extern "C" fn(
			id: *const std::os::raw::c_char,
			mechanism: sys::KEYGEN_SIGN_MECHANISM,
			parameters: *const std::ffi::c_void,
			digest: *const std::os::raw::c_uchar,
			digest_len: usize,
			signature: *mut std::os::raw::c_uchar,
			signature_len: *mut usize,
		) -> sys::KEYGEN_ERROR,

		verify: unsafe extern "C" fn(
			id: *const std::os::raw::c_char,
			mechanism: sys::KEYGEN_SIGN_MECHANISM,
			parameters: *const std::ffi::c_void,
			digest: *const std::os::raw::c_uchar,
			digest_len: usize,
			signature: *const std::os::raw::c_uchar,
			signature_len: usize,
			ok: *mut std::os::raw::c_int,
		) -> sys::KEYGEN_ERROR,

		encrypt: unsafe extern "C" fn(
			id: *const std::os::raw::c_char,
			mechanism: sys::KEYGEN_SIGN_MECHANISM,
			parameters: *const std::ffi::c_void,
			plaintext: *const std::os::raw::c_uchar,
			plaintext_len: usize,
			ciphertext: *mut std::os::raw::c_uchar,
			ciphertext_len: *mut usize,
		) -> sys::KEYGEN_ERROR,

		decrypt: unsafe extern "C" fn(
			id: *const std::os::raw::c_char,
			mechanism: sys::KEYGEN_SIGN_MECHANISM,
			parameters: *const std::ffi::c_void,
			ciphertext: *const std::os::raw::c_uchar,
			ciphertext_len: usize,
			plaintext: *mut std::os::raw::c_uchar,
			plaintext_len: *mut usize,
		) -> sys::KEYGEN_ERROR,
	},
}

impl Keys {
	pub(crate) fn new() -> Result<Self, LoadLibraryError> {
		unsafe {
			let mut function_list: *const sys::KEYGEN_FUNCTION_LIST = std::ptr::null_mut();
			keys_fn(|| sys::KEYGEN_get_function_list(sys::KEYGEN_VERSION_2_0_0_0, &mut function_list)).map_err(LoadLibraryError::GetFunctionList)?;

			let api_version = (*function_list).version;
			if api_version != sys::KEYGEN_VERSION_2_0_0_0 {
				return Err(LoadLibraryError::UnsupportedApiVersion(api_version));
			}

			// KEYGEN_FUNCTION_LIST has looser alignment than KEYGEN_FUNCTION_LIST_2_0_0_0, but the pointer comes from the library itself,
			// so it will be correctly aligned already.
			#[allow(clippy::cast_ptr_alignment)]
			let function_list: *const sys::KEYGEN_FUNCTION_LIST_2_0_0_0 = function_list as _;

			let result = Keys::V2_0_0_0 {
				set_parameter:
					(*function_list).set_parameter.ok_or(LoadLibraryError::MissingFunction("set_parameter"))?,

				create_key_pair_if_not_exists:
					(*function_list).create_key_pair_if_not_exists.ok_or(LoadLibraryError::MissingFunction("create_key_pair_if_not_exists"))?,

				load_key_pair:
					(*function_list).load_key_pair.ok_or(LoadLibraryError::MissingFunction("load_key_pair"))?,

				get_key_pair_parameter:
					(*function_list).get_key_pair_parameter.ok_or(LoadLibraryError::MissingFunction("get_key_pair_parameter"))?,

				create_key_if_not_exists:
					(*function_list).create_key_if_not_exists.ok_or(LoadLibraryError::MissingFunction("create_key_if_not_exists"))?,

				import_key:
					(*function_list).import_key.ok_or(LoadLibraryError::MissingFunction("import_key"))?,

				sign:
					(*function_list).sign.ok_or(LoadLibraryError::MissingFunction("sign"))?,

				verify:
					(*function_list).verify.ok_or(LoadLibraryError::MissingFunction("verify"))?,

				encrypt:
					(*function_list).encrypt.ok_or(LoadLibraryError::MissingFunction("encrypt"))?,

				decrypt:
					(*function_list).decrypt.ok_or(LoadLibraryError::MissingFunction("decrypt"))?,
			};

			println!("Loaded libaziot-keys with version 0x{:08x}, {:?}", api_version, result);

			Ok(result)
		}
	}
}

#[derive(Debug)]
pub enum LoadLibraryError {
	GetFunctionList(KeysRawError),
	MissingFunction(&'static str),
	UnsupportedApiVersion(sys::KEYGEN_VERSION),
}

impl std::fmt::Display for LoadLibraryError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			LoadLibraryError::GetFunctionList(inner) => write!(f, "could not get function list: {}", inner),
			LoadLibraryError::MissingFunction(name) => write!(f, "library does not define {}", name),
			LoadLibraryError::UnsupportedApiVersion(api_version) => write!(f, "library exports API version 0x{:08x} which is not supported", api_version),
		}
	}
}

impl std::error::Error for LoadLibraryError {
}

impl Keys {
	pub(crate) fn set_parameter(&mut self, name: &std::ffi::CStr, value: &std::ffi::CStr) -> Result<(), SetLibraryParameterError> {
		unsafe {
			match self {
				Keys::V2_0_0_0 { set_parameter, .. } => {
					keys_fn(|| set_parameter(
						name.as_ptr(),
						value.as_ptr(),
					)).map_err(|err| SetLibraryParameterError { name: name.to_string_lossy().into_owned(), err })?;

					Ok(())
				},
			}
		}
	}
}

#[derive(Debug)]
pub struct SetLibraryParameterError {
	name: String,
	err: KeysRawError,
}

impl std::fmt::Display for SetLibraryParameterError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "could not set {} parameter on library: {}", self.name, self.err)
	}
}

impl std::error::Error for SetLibraryParameterError {
}

impl Keys {
	pub(crate) fn create_key_pair_if_not_exists(
		&mut self,
		id: &std::ffi::CStr,
		preferred_algorithms: Option<&std::ffi::CStr>,
	) -> Result<(), CreateKeyPairIfNotExistsError> {
		unsafe {
			match self {
				Keys::V2_0_0_0 { create_key_pair_if_not_exists, .. } => {
					keys_fn(|| create_key_pair_if_not_exists(
						id.as_ptr(),
						preferred_algorithms.map_or(std::ptr::null(), |preferred_algorithms| preferred_algorithms.as_ptr()),
					)).map_err(|err| CreateKeyPairIfNotExistsError { err })?;

					Ok(())
				},
			}
		}
	}
}

#[derive(Debug)]
pub struct CreateKeyPairIfNotExistsError {
	pub err: KeysRawError,
}

impl std::fmt::Display for CreateKeyPairIfNotExistsError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "could not create key pair: {}", self.err)
	}
}

impl std::error::Error for CreateKeyPairIfNotExistsError {
}

impl Keys {
	pub(crate) fn load_key_pair(
		&mut self,
		id: &std::ffi::CStr,
	) -> Result<(), LoadKeyPairError> {
		unsafe {
			match self {
				Keys::V2_0_0_0 { load_key_pair, .. } => {
					keys_fn(|| load_key_pair(
						id.as_ptr(),
					)).map_err(|err| LoadKeyPairError { err })?;

					Ok(())
				},
			}
		}
	}
}

#[derive(Debug)]
pub struct LoadKeyPairError {
	pub err: KeysRawError,
}

impl std::fmt::Display for LoadKeyPairError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "could not load key pair: {}", self.err)
	}
}

impl std::error::Error for LoadKeyPairError {
}

impl Keys {
	pub(crate) fn get_key_pair_public_parameter(
		&mut self,
		id: &std::ffi::CStr,
		parameter_name: &str,
	) -> Result<String, GetKeyPairPublicParameterError> {
		unsafe {
			match self {
				Keys::V2_0_0_0 { get_key_pair_parameter, .. } => {
					match parameter_name {
						"algorithm" => {
							let mut algorithm: sys::KEYGEN_KEY_PAIR_PARAMETER_ALGORITHM = 0;
							let mut algorithm_len = std::mem::size_of_val(&algorithm);

							keys_fn(|| get_key_pair_parameter(
								id.as_ptr(),
								sys::KEYGEN_KEY_PAIR_PARAMETER_TYPE_ALGORITHM,
								&mut algorithm as *mut _ as _,
								&mut algorithm_len,
							)).map_err(|err| GetKeyPairPublicParameterError::Api { err })?;

							if algorithm_len != std::mem::size_of_val(&algorithm) {
								return Err(GetKeyPairPublicParameterError::UnrecognizedKeyAlgorithmLength { algorithm_len });
							}

							let algorithm = match algorithm {
								sys::KEYGEN_KEY_PAIR_PARAMETER_ALGORITHM_EC => "ECDSA".to_owned(),
								sys::KEYGEN_KEY_PAIR_PARAMETER_ALGORITHM_RSA => "RSA".to_owned(),
								algorithm => return Err(GetKeyPairPublicParameterError::UnrecognizedKeyAlgorithm { algorithm }),
							};
							Ok(algorithm)
						},

						parameter_name => {
							// These are all byte-buf parameters, so they can be handled identically.

							let parameter_type = match parameter_name {
								"ec-curve-oid" => sys::KEYGEN_KEY_PAIR_PARAMETER_TYPE_EC_CURVE_OID,
								"ec-point" => sys::KEYGEN_KEY_PAIR_PARAMETER_TYPE_EC_POINT,
								"rsa-modulus" => sys::KEYGEN_KEY_PAIR_PARAMETER_TYPE_RSA_MODULUS,
								"rsa-exponent" => sys::KEYGEN_KEY_PAIR_PARAMETER_TYPE_RSA_EXPONENT,
								_ => return Err(GetKeyPairPublicParameterError::Api { err: KeysRawError(sys::KEYGEN_ERROR_INVALID_PARAMETER) }),
							};

							let parameter_value =
								get_key_pair_parameter_byte_buf(
									*get_key_pair_parameter,
									id,
									parameter_type,
								)
								.map_err(|err| GetKeyPairPublicParameterError::Api { err })?;
							let parameter_value = base64::encode(&parameter_value);
							Ok(parameter_value)
						},
					}
				},
			}
		}
	}
}

#[derive(Debug)]
pub enum GetKeyPairPublicParameterError {
	Api { err: KeysRawError },
	UnrecognizedKeyAlgorithm { algorithm: sys::KEYGEN_KEY_PAIR_PARAMETER_ALGORITHM },
	UnrecognizedKeyAlgorithmLength { algorithm_len: usize },
}

impl std::fmt::Display for GetKeyPairPublicParameterError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			GetKeyPairPublicParameterError::Api { err } =>
				write!(f, "could not get key pair parameter: {}", err),
			GetKeyPairPublicParameterError::UnrecognizedKeyAlgorithm { algorithm } =>
				write!(f, "could not get key pair parameter: key has unknown algorithm {}", algorithm),
			GetKeyPairPublicParameterError::UnrecognizedKeyAlgorithmLength { algorithm_len } =>
				write!(f, "could not get key pair parameter: key has unknown algorithm value of length {}", algorithm_len),
		}
	}
}

impl std::error::Error for GetKeyPairPublicParameterError {
}

impl Keys {
	pub(crate) fn create_key_if_not_exists(
		&mut self,
		id: &std::ffi::CStr,
		length: usize,
	) -> Result<(), CreateKeyIfNotExistsError> {
		unsafe {
			match self {
				Keys::V2_0_0_0 { create_key_if_not_exists, .. } => {
					keys_fn(|| create_key_if_not_exists(
						id.as_ptr(),
						length,
					)).map_err(|err| CreateKeyIfNotExistsError { err })?;

					Ok(())
				},
			}
		}
	}
}

#[derive(Debug)]
pub struct CreateKeyIfNotExistsError {
	pub err: KeysRawError,
}

impl std::fmt::Display for CreateKeyIfNotExistsError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "could not create key: {}", self.err)
	}
}

impl std::error::Error for CreateKeyIfNotExistsError {
}

impl Keys {
	pub(crate) fn import_key(
		&mut self,
		id: &std::ffi::CStr,
		bytes: &[u8],
	) -> Result<(), ImportKeyError> {
		unsafe {
			match self {
				Keys::V2_0_0_0 { import_key, .. } => {
					keys_fn(|| import_key(
						id.as_ptr(),
						bytes.as_ptr(),
						bytes.len(),
					)).map_err(|err| ImportKeyError { err })?;

					Ok(())
				},
			}
		}
	}
}

#[derive(Debug)]
pub struct ImportKeyError {
	pub err: KeysRawError,
}

impl std::fmt::Display for ImportKeyError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "could not import key: {}", self.err)
	}
}

impl std::error::Error for ImportKeyError {
}

impl Keys {
	pub(crate) fn sign(
		&mut self,
		id: &std::ffi::CStr,
		mechanism: sys::KEYGEN_SIGN_MECHANISM,
		parameters: *const std::ffi::c_void,
		digest: &[u8],
	) -> Result<Vec<u8>, SignError> {
		unsafe {
			match self {
				Keys::V2_0_0_0 { sign, .. } => {
					let digest_len = std::convert::TryInto::try_into(digest.len()).expect("usize -> c_ulong");

					let mut signature_len = 0;

					keys_fn(|| sign(
						id.as_ptr(),
						mechanism,
						parameters,
						digest.as_ptr(),
						digest_len,
						std::ptr::null_mut(),
						&mut signature_len,
					)).map_err(|err| SignError { err })?;

					let mut signature = {
						let signature_len = std::convert::TryInto::try_into(signature_len).expect("c_ulong -> usize");
						vec![0_u8; signature_len]
					};

					keys_fn(|| sign(
						id.as_ptr(),
						mechanism,
						parameters,
						digest.as_ptr(),
						digest_len,
						signature.as_mut_ptr(),
						&mut signature_len,
					)).map_err(|err| SignError { err })?;

					let signature_len = std::convert::TryInto::try_into(signature_len).expect("c_ulong -> usize");

					if signature_len > signature.len() {
						// libaziot-keys scribbled past the end of the buffer. Crash as soon as possible.
						std::process::abort();
					}

					signature.resize(signature_len, 0);

					Ok(signature)
				},
			}
		}
	}
}

#[derive(Debug)]
pub struct SignError {
	pub err: KeysRawError,
}

impl std::fmt::Display for SignError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "could not sign: {}", self.err)
	}
}

impl std::error::Error for SignError {
}

impl Keys {
	pub(crate) fn verify(
		&mut self,
		id: &std::ffi::CStr,
		mechanism: sys::KEYGEN_SIGN_MECHANISM,
		parameters: *const std::ffi::c_void,
		digest: &[u8],
		signature: &[u8],
	) -> Result<bool, VerifyError> {
		unsafe {
			match self {
				Keys::V2_0_0_0 { verify, .. } => {
					let digest_len = std::convert::TryInto::try_into(digest.len()).expect("usize -> c_ulong");
					let signature_len = std::convert::TryInto::try_into(signature.len()).expect("usize -> c_ulong");

					let mut ok = 0;

					keys_fn(|| verify(
						id.as_ptr(),
						mechanism,
						parameters,
						digest.as_ptr(),
						digest_len,
						signature.as_ptr(),
						signature_len,
						&mut ok,
					)).map_err(|err| VerifyError { err })?;

					let ok = ok != 0;
					Ok(ok)
				},
			}
		}
	}
}

#[derive(Debug)]
pub struct VerifyError {
	pub err: KeysRawError,
}

impl std::fmt::Display for VerifyError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "could not verify: {}", self.err)
	}
}

impl std::error::Error for VerifyError {
}

impl Keys {
	pub(crate) fn encrypt(
		&mut self,
		id: &std::ffi::CStr,
		mechanism: sys::KEYGEN_ENCRYPT_MECHANISM,
		parameters: *const std::ffi::c_void,
		plaintext: &[u8],
	) -> Result<Vec<u8>, EncryptError> {
		unsafe {
			match self {
				Keys::V2_0_0_0 { encrypt, .. } => {
					let plaintext_len = std::convert::TryInto::try_into(plaintext.len()).expect("usize -> c_ulong");

					let mut ciphertext_len = 0;

					keys_fn(|| encrypt(
						id.as_ptr(),
						mechanism,
						parameters,
						plaintext.as_ptr(),
						plaintext_len,
						std::ptr::null_mut(),
						&mut ciphertext_len,
					)).map_err(|err| EncryptError { err })?;

					let mut ciphertext = {
						let ciphertext_len = std::convert::TryInto::try_into(ciphertext_len).expect("c_ulong -> usize");
						vec![0_u8; ciphertext_len]
					};

					keys_fn(|| encrypt(
						id.as_ptr(),
						mechanism,
						parameters,
						plaintext.as_ptr(),
						plaintext_len,
						ciphertext.as_mut_ptr(),
						&mut ciphertext_len,
					)).map_err(|err| EncryptError { err })?;

					let ciphertext_len = std::convert::TryInto::try_into(ciphertext_len).expect("c_ulong -> usize");

					if ciphertext_len > ciphertext.len() {
						// libaziot-keys scribbled past the end of the buffer. Crash as soon as possible.
						std::process::abort();
					}

					ciphertext.resize(ciphertext_len, 0);

					Ok(ciphertext)
				},
			}
		}
	}
}

#[derive(Debug)]
pub struct EncryptError {
	pub err: KeysRawError,
}

impl std::fmt::Display for EncryptError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "could not encrypt: {}", self.err)
	}
}

impl std::error::Error for EncryptError {
}

impl Keys {
	pub(crate) fn decrypt(
		&mut self,
		id: &std::ffi::CStr,
		mechanism: sys::KEYGEN_ENCRYPT_MECHANISM,
		parameters: *const std::ffi::c_void,
		ciphertext: &[u8],
	) -> Result<Vec<u8>, DecryptError> {
		unsafe {
			match self {
				Keys::V2_0_0_0 { decrypt, .. } => {
					let ciphertext_len = std::convert::TryInto::try_into(ciphertext.len()).expect("usize -> c_ulong");

					let mut plaintext_len = 0;

					keys_fn(|| decrypt(
						id.as_ptr(),
						mechanism,
						parameters,
						ciphertext.as_ptr(),
						ciphertext_len,
						std::ptr::null_mut(),
						&mut plaintext_len,
					)).map_err(|err| DecryptError { err })?;

					let mut plaintext = {
						let plaintext_len = std::convert::TryInto::try_into(plaintext_len).expect("c_ulong -> usize");
						vec![0_u8; plaintext_len]
					};

					keys_fn(|| decrypt(
						id.as_ptr(),
						mechanism,
						parameters,
						ciphertext.as_ptr(),
						ciphertext_len,
						plaintext.as_mut_ptr(),
						&mut plaintext_len,
					)).map_err(|err| DecryptError { err })?;

					let plaintext_len = std::convert::TryInto::try_into(plaintext_len).expect("c_ulong -> usize");

					if plaintext_len > plaintext.len() {
						// libaziot-keys scribbled past the end of the buffer. Crash as soon as possible.
						std::process::abort();
					}

					plaintext.resize(plaintext_len, 0);

					Ok(plaintext)
				},
			}
		}
	}
}

#[derive(Debug)]
pub struct DecryptError {
	pub err: KeysRawError,
}

impl std::fmt::Display for DecryptError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "could not decrypt: {}", self.err)
	}
}

impl std::error::Error for DecryptError {
}

fn keys_fn(f: impl FnOnce() -> sys::KEYGEN_ERROR) -> Result<(), KeysRawError> {
	match f() {
		sys::KEYGEN_SUCCESS => Ok(()),
		err => Err(KeysRawError(err)),
	}
}

unsafe fn get_key_pair_parameter_byte_buf(
	get_key_pair_parameter: unsafe extern "C" fn(
		id: *const std::os::raw::c_char,
		r#type: sys::KEYGEN_KEY_PAIR_PARAMETER_TYPE,
		value: *mut std::os::raw::c_uchar,
		value_len: *mut usize,
	) -> sys::KEYGEN_ERROR,
	id: &std::ffi::CStr,
	r#type: sys::KEYGEN_KEY_PAIR_PARAMETER_TYPE,
) -> Result<Vec<u8>, KeysRawError> {
	let mut value_len: usize = 0;

	keys_fn(|| get_key_pair_parameter(
		id.as_ptr(),
		r#type,
		std::ptr::null_mut(),
		&mut value_len,
	))?;

	let mut value = vec![0_u8; value_len];

	keys_fn(|| get_key_pair_parameter(
		id.as_ptr(),
		r#type,
		value.as_mut_ptr(),
		&mut value_len,
	))?;

	if value_len > value.len() {
		// libaziot-keys scribbled past the end of the buffer. Crash as soon as possible.
		std::process::abort();
	}

	Ok(value)
}

pub(crate) mod sys {
	#![allow(
		non_camel_case_types,
		non_snake_case,
		unused,
		clippy::unreadable_literal,
	)]

	use openssl_sys::EVP_PKEY;

	include!("keys.generated.rs");
}
