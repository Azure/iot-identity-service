pub(crate) unsafe extern "C" fn create_key_if_not_exists(
	id: *const std::os::raw::c_char,
	length: usize,
) -> crate::KEYGEN_ERROR {
	crate::r#catch(|| {
		let id = {
			if id.is_null() {
				return Err(crate::implementation::err_invalid_parameter("id", "expected non-NULL"));
			}
			let id = std::ffi::CStr::from_ptr(id);
			let id = id.to_str().map_err(|err| crate::implementation::err_invalid_parameter("id", err))?;
			id
		};

		let location = crate::implementation::Location::of(id)?;

		if load_inner(&location)?.is_none() {
			let mut bytes = vec![0_u8; length];
			openssl::rand::rand_bytes(&mut bytes)?;

			let location = crate::implementation::Location::of(id)?;

			create_inner(&location, &bytes)?;
			if load_inner(&location)?.is_none() {
				return Err(crate::implementation::err_external("key created successfully but could not be found"));
			}
		}

		Ok(())
	})
}

pub(crate) unsafe extern "C" fn import_key(
	id: *const std::os::raw::c_char,
	bytes: *const u8,
	bytes_length: usize,
) -> crate::KEYGEN_ERROR {
	crate::r#catch(|| {
		let id = {
			if id.is_null() {
				return Err(crate::implementation::err_invalid_parameter("id", "expected non-NULL"));
			}
			let id = std::ffi::CStr::from_ptr(id);
			let id = id.to_str().map_err(|err| crate::implementation::err_invalid_parameter("id", err))?;
			id
		};

		if bytes.is_null() {
			return Err(crate::implementation::err_invalid_parameter("bytes", "expected non-NULL"));
		}

		let bytes = std::slice::from_raw_parts(bytes, bytes_length);

		let location = crate::implementation::Location::of(id)?;

		create_inner(&location, bytes)?;
		if load_inner(&location)?.is_none() {
			return Err(crate::implementation::err_external("key created successfully but could not be found"));
		}

		Ok(())
	})
}

pub(crate) unsafe fn sign(
	location: &crate::implementation::Location,
	digest: &[u8],
) -> Result<(usize, Vec<u8>), crate::KEYGEN_ERROR> {
	use hmac::{Mac, NewMac};

	let key = match load_inner(location)? {
		Some(key) => key,
		None => return Err(crate::implementation::err_invalid_parameter("id", "key not found")),
	};

	let mut signer = hmac::Hmac::<sha2::Sha256>::new_varkey(&key).map_err(crate::implementation::err_external)?;

	signer.update(digest);

	let signature = signer.finalize();
	let signature = signature.into_bytes().to_vec();
	Ok((signature.len(), signature))
}

pub(crate) unsafe fn verify(
	location: &crate::implementation::Location,
	digest: &[u8],
	signature: &[u8],
) -> Result<bool, crate::KEYGEN_ERROR> {
	use hmac::{Mac, NewMac};

	let key = match load_inner(location)? {
		Some(key) => key,
		None => return Err(crate::implementation::err_invalid_parameter("id", "key not found")),
	};

	let mut signer = hmac::Hmac::<sha2::Sha256>::new_varkey(&key).map_err(crate::implementation::err_external)?;

	signer.update(digest);

	// As hmac's docs say, it's important to use `verify` here instead of just running `finalize().into_bytes()` and comparing the signatures,
	// because `verify` makes sure to be constant-time.
	let ok = signer.verify(signature).is_ok();
	Ok(ok)
}

// Ciphertext is formatted as:
//
// - Encryption scheme version (1 byte); v1 == 0x01_u8
// - Tag (16 bytes) (16 bytes is the tag size for AES-256-GCM)
// - Actual ciphertext

pub(crate) unsafe fn encrypt(
	location: &crate::implementation::Location,
	mechanism: crate::KEYGEN_ENCRYPT_MECHANISM,
	parameters: *const std::ffi::c_void,
	plaintext: &[u8],
) -> Result<(usize, Vec<u8>), crate::KEYGEN_ERROR> {
	let key = match load_inner(location)? {
		Some(key) => key,
		None => return Err(crate::implementation::err_invalid_parameter("id", "key not found")),
	};

	if mechanism != crate::KEYGEN_ENCRYPT_MECHANISM_AEAD {
		return Err(crate::implementation::err_invalid_parameter("mechanism", "unrecognized value"));
	}

	let (iv, aad) = {
		if parameters.is_null() {
			return Err(crate::implementation::err_invalid_parameter("parameters", "expected non-NULL"));
		}

		let parameters = parameters as *const crate::KEYGEN_ENCRYPT_AEAD_PARAMETERS;
		let parameters = &*parameters;

		let iv = std::slice::from_raw_parts(parameters.iv, parameters.iv_len);
		let aad = std::slice::from_raw_parts(parameters.aad, parameters.aad_len);
		(iv, aad)
	};

	let cipher = openssl::symm::Cipher::aes_256_gcm();

	let mut tag = vec![0_u8; 16];
	let ciphertext = openssl::symm::encrypt_aead(cipher, &key, Some(iv), aad, plaintext, &mut tag[..])?;

	let mut result = vec![0x01_u8];
	result.extend_from_slice(&tag);
	result.extend_from_slice(&ciphertext);
	Ok((result.len(), result))
}

pub(crate) unsafe fn decrypt(
	location: &crate::implementation::Location,
	mechanism: crate::KEYGEN_ENCRYPT_MECHANISM,
	parameters: *const std::ffi::c_void,
	ciphertext: &[u8],
) -> Result<(usize, Vec<u8>), crate::KEYGEN_ERROR> {
	let key = match load_inner(location)? {
		Some(key) => key,
		None => return Err(crate::implementation::err_invalid_parameter("id", "key not found")),
	};

	if mechanism != crate::KEYGEN_ENCRYPT_MECHANISM_AEAD {
		return Err(crate::implementation::err_invalid_parameter("mechanism", "unrecognized value"));
	}

	let (iv, aad) = {
		if parameters.is_null() {
			return Err(crate::implementation::err_invalid_parameter("parameters", "expected non-NULL"));
		}

		let parameters = parameters as *const crate::KEYGEN_ENCRYPT_AEAD_PARAMETERS;
		let parameters = &*parameters;

		let iv = std::slice::from_raw_parts(parameters.iv, parameters.iv_len);
		let aad = std::slice::from_raw_parts(parameters.aad, parameters.aad_len);
		(iv, aad)
	};

	let cipher = openssl::symm::Cipher::aes_256_gcm();

	if ciphertext.len() < 1 + 16 {
		return Err(crate::implementation::err_invalid_parameter("ciphertext", "expected non-NULL"));
	}
	if ciphertext[0] != 0x01 {
		return Err(crate::implementation::err_invalid_parameter("ciphertext", "expected non-NULL"));
	}

	let tag = &ciphertext[1..=16];
	let ciphertext = &ciphertext[17..];

	let plaintext = openssl::symm::decrypt_aead(cipher, &key, Some(iv), aad, ciphertext, tag)?;

	Ok((plaintext.len(), plaintext))
}

fn load_inner(location: &crate::implementation::Location) -> Result<Option<Vec<u8>>, crate::KEYGEN_ERROR> {
	match location {
		crate::implementation::Location::Filesystem(path) => match std::fs::read(path) {
			Ok(key_bytes) => Ok(Some(key_bytes)),
			Err(ref err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
			Err(err) => Err(crate::implementation::err_external(err)),
		},

		crate::implementation::Location::Pkcs11 { .. } =>
			Err(crate::implementation::err_external("PKCS#11 symmetric keys are not supported")),
	}
}

fn create_inner(location: &crate::implementation::Location, bytes: &[u8]) -> Result<(), crate::KEYGEN_ERROR> {
	match location {
		crate::implementation::Location::Filesystem(path) => {
			std::fs::write(&path, &bytes).map_err(crate::implementation::err_external)?;
			Ok(())
		},

		crate::implementation::Location::Pkcs11 { .. } =>
			Err(crate::implementation::err_external("PKCS#11 symmetric keys are not supported")),
	}
}
