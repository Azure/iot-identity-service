use ks_common::KeysServiceInterface;

impl crate::ex_data::HasExData<crate::ex_data::KeyExData> for openssl_sys::EC_KEY {
	unsafe fn index() -> openssl::ex_data::Index<Self, crate::ex_data::KeyExData> {
		crate::ex_data::ex_indices().ec_key
	}
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn ks_dupf_ec_key_ex_data(
	_to: *mut openssl_sys::CRYPTO_EX_DATA,
	_from: *const openssl_sys::CRYPTO_EX_DATA,
	from_d: *mut std::ffi::c_void,
	idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
	crate::ex_data::dup::<openssl_sys::EC_KEY, crate::ex_data::KeyExData>(from_d, idx);
	1
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn ks_freef_ec_key_ex_data(
	_parent: *mut std::ffi::c_void,
	ptr: *mut std::ffi::c_void,
	_ad: *mut openssl_sys::CRYPTO_EX_DATA,
	idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) {
	crate::ex_data::free::<openssl_sys::EC_KEY, crate::ex_data::KeyExData>(ptr, idx);
}

static mut OPENSSL_EC_SIGN: Option<unsafe extern "C" fn(
	ctx: *mut openssl_sys::EVP_PKEY_CTX,
	sig: *mut std::os::raw::c_uchar,
	siglen: *mut usize,
	tbs: *const std::os::raw::c_uchar,
	tbslen: usize,
) -> std::os::raw::c_int> = None;

pub(super) unsafe fn get_evp_ec_method() -> Result<*const openssl_sys2::EVP_PKEY_METHOD, openssl2::Error> {
	let openssl_method = openssl2::openssl_returns_nonnull_const(openssl_sys2::EVP_PKEY_meth_find(openssl_sys::EVP_PKEY_EC))?;
	let result =
		openssl2::openssl_returns_nonnull(
			openssl_sys2::EVP_PKEY_meth_new(openssl_sys::EVP_PKEY_EC, openssl_sys2::EVP_PKEY_FLAG_AUTOARGLEN))?;
	openssl_sys2::EVP_PKEY_meth_copy(result, openssl_method);

	let mut openssl_ec_sign_init = None;
	openssl_sys2::EVP_PKEY_meth_get_sign(openssl_method, &mut openssl_ec_sign_init, &mut OPENSSL_EC_SIGN);
	openssl_sys2::EVP_PKEY_meth_set_sign(result, openssl_ec_sign_init, Some(evp_ec_sign));

	Ok(result)
}

unsafe extern "C" fn evp_ec_sign(
	ctx: *mut openssl_sys::EVP_PKEY_CTX,
	sig: *mut std::os::raw::c_uchar,
	siglen: *mut usize,
	tbs: *const std::os::raw::c_uchar,
	tbslen: usize,
) -> std::os::raw::c_int {
	let result = super::r#catch(Some(|| super::Error::KS_EC_SIGN), || {
		let private_key = openssl2::openssl_returns_nonnull(openssl_sys2::EVP_PKEY_CTX_get0_pkey(ctx))?;
		let private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private> = foreign_types_shared::ForeignTypeRef::from_ptr(private_key);
		let ec_key = private_key.ec_key()?;
		let crate::ex_data::KeyExData { client, handle } =
			if let Ok(ex_data) = crate::ex_data::get(&*foreign_types_shared::ForeignType::as_ptr(&ec_key)) {
				ex_data
			}
			else {
				let openssl_ec_sign = OPENSSL_EC_SIGN.expect("OPENSSL_EC_SIGN must have been set by get_evp_ec_method earlier");
				match openssl_ec_sign(ctx, sig, siglen, tbs, tbslen) {
					result if result <= 0 => return Err(format!("OPENSSL_EC_SIGN returned {}", result).into()),
					_ => return Ok(()),
				}
			};

		let mechanism = ks_common::SignMechanism::Ecdsa;

		let digest = std::slice::from_raw_parts(tbs, std::convert::TryInto::try_into(tbslen).expect("c_int -> usize"));

		let signature = client.sign(handle, mechanism, digest)?;
		let signature_len = signature.len();

		if *siglen < signature_len {
			return Err(format!("openssl expected signature of length <= {} but ks returned a signature of length {}", *siglen, signature_len).into());
		}

		let signature_out = std::slice::from_raw_parts_mut(sig, *siglen);
		signature_out[..signature_len].copy_from_slice(&signature);
		*siglen = signature_len;

		Ok(())
	});
	match result {
		Ok(()) => 1,
		Err(()) => -1,
	}
}
