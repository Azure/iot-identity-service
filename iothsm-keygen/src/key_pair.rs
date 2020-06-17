pub(crate) unsafe extern "C" fn create_key_pair_if_not_exists(
	id: *const std::os::raw::c_char,
	preferred_algorithms: *const std::os::raw::c_char,
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

		let preferred_algorithms = PreferredAlgorithm::from_str(preferred_algorithms).map_err(|err| crate::implementation::err_invalid_parameter("preferred_algorithms", err))?;

		let location = crate::implementation::Location::of(id)?;

		if load_inner(&location)?.is_none() {
			create_inner(&location, &preferred_algorithms)?;
			if load_inner(&location)?.is_none() {
				return Err(crate::implementation::err_external("key created successfully but could not be found"));
			}
		}

		Ok(())
	})
}

pub(crate) unsafe extern "C" fn load_key_pair(
	id: *const std::os::raw::c_char,
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
			return Err(crate::implementation::err_invalid_parameter("id", "not found"));
		}

		Ok(())
	})
}

pub(crate) unsafe extern "C" fn get_key_pair_parameter(
	id: *const std::os::raw::c_char,
	r#type: crate::KEYGEN_KEY_PAIR_PARAMETER_TYPE,
	value: *mut std::os::raw::c_uchar,
	value_len: *mut usize,
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

		let mut value_len_out = std::ptr::NonNull::new(value_len).ok_or_else(|| crate::implementation::err_invalid_parameter("value_len", "expected non-NULL"))?;

		let location = crate::implementation::Location::of(id)?;

		let (public_key, _) = load_inner(&location)?.ok_or_else(|| crate::implementation::err_invalid_parameter("id", "not found"))?;

		match r#type {
			crate::KEYGEN_KEY_PAIR_PARAMETER_TYPE_ALGORITHM => {
				let expected_value_len = std::mem::size_of::<crate::KEYGEN_KEY_PAIR_PARAMETER_ALGORITHM>();
				let actual_value_len = *value_len_out.as_ref();

				*value_len_out.as_mut() = expected_value_len;

				if !value.is_null() {
					if actual_value_len < expected_value_len {
						return Err(crate::implementation::err_invalid_parameter("value", "insufficient size"));
					}

					let value_out = std::slice::from_raw_parts_mut(value, actual_value_len);

					let value =
						if public_key.ec_key().is_ok() {
							crate::KEYGEN_KEY_PAIR_PARAMETER_ALGORITHM_EC
						}
						else if public_key.rsa().is_ok() {
							crate::KEYGEN_KEY_PAIR_PARAMETER_ALGORITHM_RSA
						}
						else {
							return Err(crate::implementation::err_invalid_parameter("id", "key is neither RSA nor EC"));
						};
					let value = value.inner.to_ne_bytes();
					value_out[..expected_value_len].copy_from_slice(&value[..]);
				}

				Ok(())
			},

			crate::KEYGEN_KEY_PAIR_PARAMETER_TYPE_EC_CURVE_OID => {
				let ec_key =
					if let Ok(ec_key) = public_key.ec_key() {
						ec_key
					}
					else {
						return Err(crate::implementation::err_invalid_parameter("type", "not an EC key"));
					};

				let curve_nid = ec_key.group().curve_name().ok_or_else(|| crate::implementation::err_invalid_parameter("type", "key does not have named curve"))?;
				let curve = openssl2::EcCurve::from_nid(curve_nid).ok_or_else(|| crate::implementation::err_invalid_parameter("type", "key curve not recognized"))?;
				let curve_oid = curve.as_oid_der();

				let expected_value_len = curve_oid.len();
				let actual_value_len = *value_len_out.as_ref();

				*value_len_out.as_mut() = expected_value_len;

				if !value.is_null() {
					if actual_value_len < expected_value_len {
						return Err(crate::implementation::err_invalid_parameter("value", "insufficient size"));
					}

					let value_out = std::slice::from_raw_parts_mut(value, actual_value_len);

					value_out[..expected_value_len].copy_from_slice(curve_oid);
				}

				Ok(())
			},

			crate::KEYGEN_KEY_PAIR_PARAMETER_TYPE_EC_POINT => {
				let ec_key =
					if let Ok(ec_key) = public_key.ec_key() {
						ec_key
					}
					else {
						return Err(crate::implementation::err_invalid_parameter("type", "not an EC key"));
					};

				let curve = ec_key.group();
				let point = ec_key.public_key();
				let mut big_num_context = openssl::bn::BigNumContext::new()?;
				let point = point.to_bytes(curve, openssl::ec::PointConversionForm::COMPRESSED, &mut big_num_context)?;

				let expected_value_len = point.len();
				let actual_value_len = *value_len_out.as_ref();

				*value_len_out.as_mut() = expected_value_len;

				if !value.is_null() {
					if actual_value_len < expected_value_len {
						return Err(crate::implementation::err_invalid_parameter("value", "insufficient size"));
					}

					let value_out = std::slice::from_raw_parts_mut(value, actual_value_len);

					value_out[..expected_value_len].copy_from_slice(&point);
				}

				Ok(())
			},

			crate::KEYGEN_KEY_PAIR_PARAMETER_TYPE_RSA_MODULUS => {
				let rsa =
					if let Ok(rsa) = public_key.rsa() {
						rsa
					}
					else {
						return Err(crate::implementation::err_invalid_parameter("type", "not an RSA key"));
					};

				let modulus = rsa.n().to_vec();

				let expected_value_len = modulus.len();
				let actual_value_len = *value_len_out.as_ref();

				*value_len_out.as_mut() = expected_value_len;

				if !value.is_null() {
					if actual_value_len < expected_value_len {
						return Err(crate::implementation::err_invalid_parameter("value", "insufficient size"));
					}

					let value_out = std::slice::from_raw_parts_mut(value, actual_value_len);

					value_out[..expected_value_len].copy_from_slice(&modulus);
				}

				Ok(())
			},

			crate::KEYGEN_KEY_PAIR_PARAMETER_TYPE_RSA_EXPONENT => {
				let rsa =
					if let Ok(rsa) = public_key.rsa() {
						rsa
					}
					else {
						return Err(crate::implementation::err_invalid_parameter("type", "not an RSA key"));
					};

				let exponent = rsa.e().to_vec();

				let expected_value_len = exponent.len();
				let actual_value_len = *value_len_out.as_ref();

				*value_len_out.as_mut() = expected_value_len;

				if !value.is_null() {
					if actual_value_len < expected_value_len {
						return Err(crate::implementation::err_invalid_parameter("value", "insufficient size"));
					}

					let value_out = std::slice::from_raw_parts_mut(value, actual_value_len);

					value_out[..expected_value_len].copy_from_slice(&exponent);
				}

				Ok(())
			},

			_ => Err(crate::implementation::err_invalid_parameter("type", "unrecognized value")),
		}
	})
}

pub(crate) unsafe fn sign(
	location: &crate::implementation::Location,
	mechanism: crate::KEYGEN_SIGN_MECHANISM,
	parameters: *const std::ffi::c_void,
	digest: &[u8],
) -> Result<(usize, Vec<u8>), crate::KEYGEN_ERROR> {
	let (_, private_key) = load_inner(location)?.ok_or_else(|| crate::implementation::err_invalid_parameter("id", "not found"))?;

	let (signature_len, signature) = match (mechanism, private_key.ec_key(), private_key.rsa()) {
		(crate::KEYGEN_SIGN_MECHANISM_ECDSA, Ok(ec_key), _) => {
			let signature_len = {
				let ec_key = foreign_types_shared::ForeignType::as_ptr(&ec_key);
				let signature_len = openssl_sys2::ECDSA_size(ec_key);
				let signature_len =
					std::convert::TryInto::try_into(signature_len)
					.map_err(|err| crate::implementation::err_external(format!("ECDSA_size returned invalid value: {}", err)))?;
				signature_len
			};

			let signature = openssl::ecdsa::EcdsaSig::sign(digest, &ec_key)?;
			let signature = signature.to_der()?;

			(signature_len, signature)
		},

		(crate::KEYGEN_SIGN_MECHANISM_RSA_PKCS1, _, Ok(rsa)) => {
			let message_digest = {
				if parameters.is_null() {
					return Err(crate::implementation::err_invalid_parameter("parameters", "expected non-NULL"));
				}

				let parameters = parameters as *const crate::KEYGEN_RSA_PKCS1_MESSAGE_DIGEST;
				match *parameters {
					crate::KEYGEN_RSA_PKCS1_MESSAGE_DIGEST_SHA1 => openssl::hash::MessageDigest::sha1(),
					crate::KEYGEN_RSA_PKCS1_MESSAGE_DIGEST_SHA224 => openssl::hash::MessageDigest::sha224(),
					crate::KEYGEN_RSA_PKCS1_MESSAGE_DIGEST_SHA256 => openssl::hash::MessageDigest::sha256(),
					crate::KEYGEN_RSA_PKCS1_MESSAGE_DIGEST_SHA384 => openssl::hash::MessageDigest::sha384(),
					crate::KEYGEN_RSA_PKCS1_MESSAGE_DIGEST_SHA512 => openssl::hash::MessageDigest::sha512(),
					_ => return Err(crate::implementation::err_invalid_parameter("parameters", "unrecognized message digest")),
				}
			};

			// openssl crate doesn't expose a wrapper around RSA_sign, so call it directly

			let signature_len = rsa.size();
			let signature_len =
				std::convert::TryInto::try_into(signature_len)
				.map_err(|err| crate::implementation::err_external(format!("RSA_size returned invalid value: {}", err)))?;

			let signature = {
				let mut signature = vec![0_u8; signature_len];

				// It was just converted from u32 to usize above, so this is guaranteed to succeed.
				let mut signature_len = signature_len as u32;

				openssl2::openssl_returns_1(openssl_sys::RSA_sign(
					message_digest.type_().as_raw(),
					digest.as_ptr(), std::convert::TryInto::try_into(digest.len()).map_err(|err| crate::implementation::err_invalid_parameter("digest_len", err))?,
					signature.as_mut_ptr(), &mut signature_len,
					foreign_types_shared::ForeignType::as_ptr(&rsa),
				))?;

				let signature_len =
					std::convert::TryInto::try_into(signature_len)
					.map_err(|err| crate::implementation::err_external(format!("RSA_sign returned invalid signature length: {}", err)))?;
				if signature_len > signature.len() {
					// RSA_sign scribbled past the end of the buffer. Crash as soon as possible.
					std::process::abort();
				}

				signature.truncate(signature_len);

				signature
			};

			(signature_len, signature)
		},

		// crate::KEYGEN_SIGN_MECHANISM_RSA_PSS => {
		// 	if parameters.is_null() {
		// 		return Err(crate::implementation::err_invalid_parameter("parameters", "expected KEYGEN_SIGN_RSA_PSS_PARAMETERS"));
		// 	}

		// 	let parameters = &*(parameters as *const crate::KEYGEN_SIGN_RSA_PSS_PARAMETERS);

		// 	let mask_generation_function = match parameters.mask_generation_function {
		// 		crate::KEYGEN_SIGN_RSA_PSS_MASK_GENERATION_FUNCTION_SHA1 => openssl::hash::MessageDigest::sha1(),
		// 		crate::KEYGEN_SIGN_RSA_PSS_MASK_GENERATION_FUNCTION_SHA224 => openssl::hash::MessageDigest::sha224(),
		// 		crate::KEYGEN_SIGN_RSA_PSS_MASK_GENERATION_FUNCTION_SHA256 => openssl::hash::MessageDigest::sha256(),
		// 		crate::KEYGEN_SIGN_RSA_PSS_MASK_GENERATION_FUNCTION_SHA384 => openssl::hash::MessageDigest::sha384(),
		// 		crate::KEYGEN_SIGN_RSA_PSS_MASK_GENERATION_FUNCTION_SHA512 => openssl::hash::MessageDigest::sha512(),
		// 		_ => return Err(crate::implementation::err_invalid_parameter("mask_generation_function", "unrecognized value")),
		// 	};

		// 	let salt_len = std::convert::TryInto::try_into(parameters.salt_len).map_err(|err| crate::implementation::err_invalid_parameter("salt_len", err))?;
		// 	let salt_len = openssl::sign::RsaPssSaltlen::custom(salt_len);

		// 	signer.set_rsa_padding(openssl::rsa::Padding::PKCS1_PSS)?;
		// 	signer.set_rsa_mgf1_md(mask_generation_function)?;
		// 	signer.set_rsa_pss_saltlen(salt_len)?;
		// },

		_ => return Err(crate::implementation::err_invalid_parameter("mechanism", "unrecognized value")),
	};

	Ok((signature_len, signature))
}

fn load_inner(location: &crate::implementation::Location) ->
	Result<
		Option<(openssl::pkey::PKey<openssl::pkey::Public>, openssl::pkey::PKey<openssl::pkey::Private>)>,
		crate::KEYGEN_ERROR,
	>
{
	match location {
		crate::implementation::Location::Filesystem(path) => match std::fs::read(path) {
			Ok(private_key_pem) => {
				let private_key = openssl::pkey::PKey::private_key_from_pem(&private_key_pem)?;

				// Copy private_key's public parameters into a new public key
				let public_key_der = private_key.public_key_to_der()?;
				let public_key = openssl::pkey::PKey::public_key_from_der(&public_key_der)?;

				Ok(Some((public_key, private_key)))
			},

			Err(ref err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),

			Err(err) => Err(crate::implementation::err_external(err)),
		},

		crate::implementation::Location::Pkcs11 { lib_path, uri } => {
			let pkcs11_context = pkcs11::Context::load(lib_path.clone()).map_err(crate::implementation::err_external)?;
			let pkcs11_slot = pkcs11_context.find_slot(&uri.slot_identifier).map_err(crate::implementation::err_external)?;
			let pkcs11_session = pkcs11_context.clone().open_session(pkcs11_slot, uri.pin.clone()).map_err(crate::implementation::err_external)?;

			// Use PKCS#11 directly instead of the openssl engine, because PKCS#11 allows us to know the key doesn't exist,
			// whereas openssl just returns `NULL` for all errors.
			match pkcs11_session.get_key_pair(uri.object_label.as_ref().map(AsRef::as_ref)) {
				Ok(_) => (),

				Err(pkcs11::GetKeyError::KeyDoesNotExist) => return Ok(None),

				Err(err) => return Err(crate::implementation::err_external(err)),
			}

			// PKCS#11 found the key pair, so now use the openssl engine
			let key_id = uri.to_string();
			let key_id = std::ffi::CString::new(key_id).map_err(|err| crate::implementation::err_invalid_parameter("id", err))?;

			let mut engine = openssl_engine_pkcs11::load(pkcs11_context)?;

			let public_key = engine.load_public_key(&key_id)?;
			let private_key = engine.load_private_key(&key_id)?;

			Ok(Some((public_key, private_key)))
		},
	}
}

fn create_inner(location: &crate::implementation::Location, preferred_algorithms: &[PreferredAlgorithm]) -> Result<(), crate::KEYGEN_ERROR> {
	match location {
		crate::implementation::Location::Filesystem(path) => {
			let preferred_algorithm = preferred_algorithms.iter().copied().next().ok_or_else(|| crate::implementation::err_invalid_parameter("preferred_algorithms", "none specified"))?;

			let private_key = match preferred_algorithm {
				PreferredAlgorithm::NistP256 => {
					let mut group = openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)?;
					group.set_asn1_flag(openssl::ec::Asn1Flag::NAMED_CURVE);
					let ec_key = openssl::ec::EcKey::generate(&group)?;
					let private_key = openssl::pkey::PKey::from_ec_key(ec_key)?;
					private_key
				},

				PreferredAlgorithm::Rsa2048 => {
					let rsa = openssl::rsa::Rsa::generate(2048)?;
					let private_key = openssl::pkey::PKey::from_rsa(rsa)?;
					private_key
				},

				PreferredAlgorithm::Rsa4096 => {
					let rsa = openssl::rsa::Rsa::generate(4096)?;
					let private_key = openssl::pkey::PKey::from_rsa(rsa)?;
					private_key
				},
			};

			let private_key_pem = private_key.private_key_to_pem_pkcs8()?;
			std::fs::write(&path, &private_key_pem).map_err(crate::implementation::err_external)?;

			Ok(())
		},

		crate::implementation::Location::Pkcs11 { lib_path, uri } => {
			let pkcs11_context = pkcs11::Context::load(lib_path.clone()).map_err(crate::implementation::err_external)?;
			let pkcs11_slot = pkcs11_context.find_slot(&uri.slot_identifier).map_err(crate::implementation::err_external)?;
			let pkcs11_session = pkcs11_context.open_session(pkcs11_slot, uri.pin.clone()).map_err(crate::implementation::err_external)?;

			for preferred_algorithm in preferred_algorithms {
				match preferred_algorithm {
					PreferredAlgorithm::NistP256 =>
						if pkcs11_session.clone().generate_ec_key_pair(openssl2::EcCurve::NistP256, uri.object_label.as_ref().map(AsRef::as_ref)).is_ok() {
							return Ok(());
						},

					PreferredAlgorithm::Rsa2048 => {
						let exponent = openssl_sys::RSA_F4;
						let exponent = exponent.to_be_bytes();
						let exponent = openssl::bn::BigNum::from_slice(&exponent)?;

						if pkcs11_session.clone().generate_rsa_key_pair(2048, &exponent, uri.object_label.as_ref().map(AsRef::as_ref)).is_ok() {
							return Ok(());
						}
					},

					PreferredAlgorithm::Rsa4096 => {
						let exponent = openssl_sys::RSA_F4;
						let exponent = exponent.to_be_bytes();
						let exponent = openssl::bn::BigNum::from_slice(&exponent)?;

						if pkcs11_session.clone().generate_rsa_key_pair(4096, &exponent, uri.object_label.as_ref().map(AsRef::as_ref)).is_ok() {
							return Ok(());
						}
					},
				}
			}

			Err(crate::implementation::err_invalid_parameter("preferred_algorithms", "no algorithm succeeded"))
		},
	}
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum PreferredAlgorithm {
	NistP256,
	Rsa2048,
	Rsa4096,
}

impl PreferredAlgorithm {
	unsafe fn from_str(s: *const std::os::raw::c_char) -> Result<Vec<Self>, Box<dyn std::error::Error>> {
		fn add_if_not_exists<T>(v: &mut Vec<T>, element: T) where T: std::cmp::PartialEq {
			if v.iter().any(|existing| existing == &element) {
				return;
			}

			v.push(element);
		}

		if s.is_null() {
			return Ok(vec![PreferredAlgorithm::NistP256, PreferredAlgorithm::Rsa2048]);
		}

		let s = std::ffi::CStr::from_ptr(s);
		let s = s.to_str()?;
		let mut result = vec![];
		for component in s.split(':') {
			match component {
				"*" => {
					add_if_not_exists(&mut result, PreferredAlgorithm::NistP256);
					add_if_not_exists(&mut result, PreferredAlgorithm::Rsa2048);
				},

				"ec-p256" => add_if_not_exists(&mut result, PreferredAlgorithm::NistP256),

				"rsa-2048" => add_if_not_exists(&mut result, PreferredAlgorithm::Rsa2048),

				"rsa-4096" => add_if_not_exists(&mut result, PreferredAlgorithm::Rsa4096),

				_ => (),
			}
		}
		Ok(result)
	}
}
