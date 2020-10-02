// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Engine {
	client: std::sync::Arc<aziot_key_client::Client>,
}

impl Engine {
	const ENGINE_ID: &'static [u8] = b"aziot-key-openssl-engine\0";

	pub(super) unsafe fn load(client: std::sync::Arc<aziot_key_client::Client>) -> Result<openssl2::FunctionalEngine, openssl2::Error> {
		static REGISTER: std::sync::Once = std::sync::Once::new();

		REGISTER.call_once(|| {
			// If we can't complete the registration, log the error and swallow it.
			// The caller will get an error when it tries to look up the engine that failed to be created,
			// so there's no worry about propagating the error from here.
			let _ = super::r#catch(None, || {
				let e = openssl2::openssl_returns_nonnull(openssl_sys2::ENGINE_new())?;
				let e: openssl2::StructuralEngine = foreign_types_shared::ForeignType::from_ptr(e);
				let e = foreign_types_shared::ForeignType::as_ptr(&e);

				Self::register(e, None)?;

				Ok(())
			});
		});

		let e =
			openssl2::StructuralEngine::by_id(
				std::ffi::CStr::from_bytes_with_nul(Self::ENGINE_ID).expect("hard-coded engine ID is valid CStr"),
			)?;
		let e: openssl2::FunctionalEngine = std::convert::TryInto::try_into(e)?;

		Self::init(foreign_types_shared::ForeignType::as_ptr(&e), client)?;

		Ok(e)
	}

	pub(super) unsafe fn register(
		e: *mut openssl_sys::ENGINE,
		init: Option<openssl_sys2::ENGINE_GEN_INT_FUNC_PTR>,
	) -> Result<(), openssl2::Error> {
		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_id(
			e,
			std::ffi::CStr::from_bytes_with_nul(Self::ENGINE_ID)
				.expect("hard-coded engine ID is valid CStr")
				.as_ptr(),
		))?;
		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_name(
			e,
			std::ffi::CStr::from_bytes_with_nul(b"An openssl engine that talks to the Azure IoT Keys Service\0")
				.expect("hard-coded engine name is valid CStr")
				.as_ptr(),
		))?;

		if let Some(init) = init {
			openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_init_function(e, init))?;
		}

		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_load_privkey_function(e, engine_load_privkey))?;
		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_load_pubkey_function(e, engine_load_pubkey))?;
		#[cfg(ossl110)]
		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_pkey_meths(e, engine_pkey_meths))?;
		openssl2::openssl_returns_1(openssl_sys2::ENGINE_set_flags(e, openssl_sys2::ENGINE_FLAGS_BY_ID_COPY))?;

		openssl2::openssl_returns_1(openssl_sys2::ENGINE_add(e))?;

		Ok(())
	}

	pub(super) unsafe fn init(
		e: *mut openssl_sys::ENGINE,
		client: std::sync::Arc<aziot_key_client::Client>,
	) -> Result<(), openssl2::Error> {
		let engine = Engine {
			client,
		};
		crate::ex_data::set(e, engine)?;
		Ok(())
	}
}

impl crate::ex_data::HasExData<crate::engine::Engine> for openssl_sys::ENGINE {
	unsafe fn index() -> openssl::ex_data::Index<Self, crate::engine::Engine> {
		crate::ex_data::ex_indices().engine
	}
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn aziot_key_dupf_engine_ex_data(
	_to: *mut openssl_sys::CRYPTO_EX_DATA,
	_from: *const openssl_sys::CRYPTO_EX_DATA,
	from_d: *mut std::ffi::c_void,
	idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
	crate::ex_data::dup::<openssl_sys::ENGINE, crate::engine::Engine>(from_d, idx);
	1
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn aziot_key_freef_engine_ex_data(
	_parent: *mut std::ffi::c_void,
	ptr: *mut std::ffi::c_void,
	_ad: *mut openssl_sys::CRYPTO_EX_DATA,
	idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) {
	crate::ex_data::free::<openssl_sys::ENGINE, crate::engine::Engine>(ptr, idx);
}

unsafe extern "C" fn engine_load_privkey(
	e: *mut openssl_sys::ENGINE,
	key_id: *const std::os::raw::c_char,
	_ui_method: *mut openssl_sys2::UI_METHOD,
	_callback_data: *mut std::ffi::c_void,
) -> *mut openssl_sys::EVP_PKEY {
	let result = super::r#catch(Some(|| super::Error::ENGINE_LOAD_PRIVKEY), || {
		let engine = crate::ex_data::get(&*e)?;

		let client = engine.client.clone();

		let key_handle = std::ffi::CStr::from_ptr(key_id).to_str()?;
		let key_handle = aziot_key_common::KeyHandle(key_handle.to_owned());

		let key_ex_data = crate::ex_data::KeyExData {
			client: client.clone(),
			handle: key_handle.clone(),
		};

		let key_algorithm = client.get_key_pair_public_parameter(&key_handle, "algorithm")?;
		let openssl_key_raw = match &*key_algorithm {
			"ECDSA" => {
				let curve_oid = client.get_key_pair_public_parameter(&key_handle, "ec-curve-oid")?;
				let curve_oid = base64::decode(&curve_oid)?;
				let curve = openssl2::EcCurve::from_oid_der(&curve_oid).ok_or_else(|| format!("unrecognized curve {:?}", curve_oid))?;
				let curve = curve.as_nid();
				let mut group = openssl::ec::EcGroup::from_curve_name(curve)?;
				group.set_asn1_flag(openssl::ec::Asn1Flag::NAMED_CURVE);

				let point = client.get_key_pair_public_parameter(&key_handle, "ec-point")?;
				let point = base64::decode(&point)?;
				let mut big_num_context = openssl::bn::BigNumContext::new()?;
				let point =
					openssl::ec::EcPoint::from_bytes(
						&group,
						&point,
						&mut big_num_context,
					)?;

				let parameters = openssl::ec::EcKey::<openssl::pkey::Public>::from_public_key(
					&group,
					&point,
				)?;

				{
					let parameters = foreign_types_shared::ForeignType::as_ptr(&parameters);

					crate::ex_data::set(parameters, key_ex_data)?;

					#[cfg(ossl110)]
					openssl2::openssl_returns_1(openssl_sys2::EC_KEY_set_method(
						parameters,
						super::ec_key::aziot_key_ec_key_method(),
					))?;
					#[cfg(not(ossl110))]
					openssl2::openssl_returns_1(openssl_sys2::ECDSA_set_method(
						parameters,
						super::ec_key::aziot_key_ec_key_method(),
					))?;
				}

				let openssl_key = openssl::pkey::PKey::from_ec_key(parameters)?;
				let openssl_key_raw = openssl2::foreign_type_into_ptr(openssl_key);

				openssl_key_raw
			},

			"RSA" => {
				let modulus = client.get_key_pair_public_parameter(&key_handle, "rsa-modulus")?;
				let modulus = base64::decode(&modulus)?;
				let modulus = openssl::bn::BigNum::from_slice(&modulus)?;

				let exponent = client.get_key_pair_public_parameter(&key_handle, "rsa-exponent")?;
				let exponent = base64::decode(&exponent)?;
				let exponent = openssl::bn::BigNum::from_slice(&exponent)?;

				let parameters = openssl::rsa::Rsa::<openssl::pkey::Public>::from_public_components(
					modulus,
					exponent,
				)?;

				{
					let parameters = foreign_types_shared::ForeignType::as_ptr(&parameters);

					crate::ex_data::set(parameters, key_ex_data)?;

					openssl2::openssl_returns_1(openssl_sys2::RSA_set_method(
						parameters,
						super::rsa::aziot_key_rsa_method(),
					))?;
				}

				let openssl_key = openssl::pkey::PKey::from_rsa(parameters)?;
				let openssl_key_raw = openssl2::foreign_type_into_ptr(openssl_key);

				openssl_key_raw
			},

			key_algorithm => return Err(format!("unrecognized key algorithm {}", key_algorithm).into()),
		};

		// Needed for openssl 1.1, otherwise the key is not associated with the engine.
		#[cfg(ossl110)]
		openssl2::openssl_returns_1(openssl_sys2::EVP_PKEY_set1_engine(openssl_key_raw, e))?;

		Ok(openssl_key_raw)
	});
	match result {
		Ok(key) => key,
		Err(()) => std::ptr::null_mut(),
	}
}

unsafe extern "C" fn engine_load_pubkey(
	e: *mut openssl_sys::ENGINE,
	key_id: *const std::os::raw::c_char,
	_ui_method: *mut openssl_sys2::UI_METHOD,
	_callback_data: *mut std::ffi::c_void,
) -> *mut openssl_sys::EVP_PKEY {
	let result = super::r#catch(Some(|| super::Error::ENGINE_LOAD_PUBKEY), || {
		let engine = crate::ex_data::get(&*e)?;

		let key_handle = std::ffi::CStr::from_ptr(key_id).to_str()?;
		let key_handle = aziot_key_common::KeyHandle(key_handle.to_owned());

		let client = engine.client.clone();

		let key_algorithm = client.get_key_pair_public_parameter(&key_handle, "algorithm")?;
		let openssl_key_raw = match &*key_algorithm {
			"ECDSA" => {
				let curve_oid = client.get_key_pair_public_parameter(&key_handle, "ec-curve-oid")?;
				let curve_oid = base64::decode(&curve_oid)?;
				let curve = openssl2::EcCurve::from_oid_der(&curve_oid).ok_or_else(|| format!("unrecognized curve {:?}", curve_oid))?;
				let curve = curve.as_nid();
				let mut group = openssl::ec::EcGroup::from_curve_name(curve)?;
				group.set_asn1_flag(openssl::ec::Asn1Flag::NAMED_CURVE);

				let point = client.get_key_pair_public_parameter(&key_handle, "ec-point")?;
				let point = base64::decode(&point)?;
				let mut big_num_context = openssl::bn::BigNumContext::new()?;
				let point =
					openssl::ec::EcPoint::from_bytes(
						&group,
						&point,
						&mut big_num_context,
					)?;

				let parameters = openssl::ec::EcKey::<openssl::pkey::Public>::from_public_key(
					&group,
					&point,
				)?;

				let openssl_key = openssl::pkey::PKey::from_ec_key(parameters)?;
				let openssl_key_raw = openssl2::foreign_type_into_ptr(openssl_key);

				openssl_key_raw
			},

			"RSA" => {
				let modulus = client.get_key_pair_public_parameter(&key_handle, "rsa-modulus")?;
				let modulus = base64::decode(&modulus)?;
				let modulus = openssl::bn::BigNum::from_slice(&modulus)?;

				let exponent = client.get_key_pair_public_parameter(&key_handle, "rsa-exponent")?;
				let exponent = base64::decode(&exponent)?;
				let exponent = openssl::bn::BigNum::from_slice(&exponent)?;

				let parameters = openssl::rsa::Rsa::<openssl::pkey::Public>::from_public_components(
					modulus,
					exponent,
				)?;

				let openssl_key = openssl::pkey::PKey::from_rsa(parameters)?;
				let openssl_key_raw = openssl2::foreign_type_into_ptr(openssl_key);

				openssl_key_raw
			},

			key_algorithm => return Err(format!("unrecognized key algorithm {}", key_algorithm).into()),
		};

		Ok(openssl_key_raw)
	});
	match result {
		Ok(key) => key,
		Err(()) => std::ptr::null_mut(),
	}
}

#[cfg(ossl110)]
unsafe extern "C" fn engine_pkey_meths(
	_e: *mut openssl_sys::ENGINE,
	pmeth: *mut *const openssl_sys2::EVP_PKEY_METHOD,
	nids: *mut *const std::os::raw::c_int,
	nid: std::os::raw::c_int,
) -> std::os::raw::c_int {
	// Two modes of operation:
	//
	// 1. pmeths is NULL, nids is not NULL, nid is ignored
	//
	//    The caller wants us to populate all the nids we support in nids. Return the number of nids.
	//
	// 2. pmeths is not NULL, nids is ignored, nid is not 0
	//
	//    The caller wants us to populate the methods of nid in pmeths. Return non-zero on success, zero on failure.

	let result = super::r#catch(Some(|| super::Error::ENGINE_PKEY_METHS), || {
		const SUPPORTED_NIDS: &[std::os::raw::c_int] = &[
			openssl_sys::EVP_PKEY_EC,
			openssl_sys::EVP_PKEY_RSA,
		];

		if pmeth.is_null() {
			// Mode 1

			if !nids.is_null() {
				*nids = SUPPORTED_NIDS.as_ptr();
			}

			Ok(std::convert::TryInto::try_into(SUPPORTED_NIDS.len()).expect("usize -> c_int"))
		}
		else {
			// Mode 2

			match nid {
				openssl_sys::EVP_PKEY_EC => {
					*pmeth = super::ec_key::get_evp_ec_method()?;
					Ok(1)
				},

				openssl_sys::EVP_PKEY_RSA => {
					*pmeth = super::rsa::get_evp_rsa_method()?;
					Ok(1)
				},

				nid => Err(format!("unsupported nid 0x{:08x}", nid).into()),
			}
		}
	});
	match result {
		Ok(result) => result,
		Err(()) => 0,
	}
}
