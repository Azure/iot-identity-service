impl crate::ex_data::HasExData<crate::ex_data::KeyExData> for openssl_sys::RSA {
	unsafe fn index() -> openssl::ex_data::Index<Self, crate::ex_data::KeyExData> {
		crate::ex_data::ex_indices().rsa
	}
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn aziot_key_dupf_rsa_ex_data(
	_to: *mut openssl_sys::CRYPTO_EX_DATA,
	_from: *const openssl_sys::CRYPTO_EX_DATA,
	from_d: *mut std::ffi::c_void,
	idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
	crate::ex_data::dup::<openssl_sys::RSA, crate::ex_data::KeyExData>(from_d, idx);
	1
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn aziot_key_freef_rsa_ex_data(
	_parent: *mut std::ffi::c_void,
	ptr: *mut std::ffi::c_void,
	_ad: *mut openssl_sys::CRYPTO_EX_DATA,
	idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) {
	crate::ex_data::free::<openssl_sys::RSA, crate::ex_data::KeyExData>(ptr, idx);
}

#[cfg(ossl110)]
static mut OPENSSL_EVP_RSA_SIGN: Option<unsafe extern "C" fn (
	ctx: *mut openssl_sys::EVP_PKEY_CTX,
	sig: *mut std::os::raw::c_uchar,
	siglen: *mut usize,
	tbs: *const std::os::raw::c_uchar,
	tbslen: usize,
) -> std::os::raw::c_int> = None;

#[cfg(ossl110)]
pub(super) unsafe fn get_evp_rsa_method() -> Result<*const openssl_sys2::EVP_PKEY_METHOD, openssl2::Error> {
	// The default RSA method works fine but for one problem. When signing with a PSS key,
	// it does the PSS padding itself and then invokes the key's encrypt function with RSA_NO_PADDING for raw encryption.
	// The PKCS#11 equivalent of RSA_NO_PADDING is the CKM_RSA_X_509 mechanism, 
	// which PKCS#11 implementations don't necessarily implement for security reasons.
	//
	// So we want to override the method, detect that we're doing PSS signing, and directly invoke the Key Service sign operation
	// with the RsaPss mechanism instead.

	let openssl_method = openssl2::openssl_returns_nonnull_const(openssl_sys2::EVP_PKEY_meth_find(openssl_sys::EVP_PKEY_RSA))?;
	let result =
		openssl2::openssl_returns_nonnull(
			openssl_sys2::EVP_PKEY_meth_new(openssl_sys::EVP_PKEY_RSA, openssl_sys2::EVP_PKEY_FLAG_AUTOARGLEN))?;
	openssl_sys2::EVP_PKEY_meth_copy(result, openssl_method);

	let mut openssl_rsa_sign_init = None;
	openssl_sys2::EVP_PKEY_meth_get_sign(openssl_method, &mut openssl_rsa_sign_init, &mut OPENSSL_EVP_RSA_SIGN);
	openssl_sys2::EVP_PKEY_meth_set_sign(result, openssl_rsa_sign_init, Some(aziot_key_evp_rsa_sign));

	Ok(result)
}

#[cfg(ossl110)]
unsafe extern "C" fn aziot_key_evp_rsa_sign(
	ctx: *mut openssl_sys::EVP_PKEY_CTX,
	sig: *mut std::os::raw::c_uchar,
	siglen: *mut usize,
	tbs: *const std::os::raw::c_uchar,
	tbslen: usize,
) -> std::os::raw::c_int {
	let result = super::r#catch(Some(|| super::Error::AZIOT_KEY_RSA_SIGN), || {
		let private_key = openssl2::openssl_returns_nonnull(openssl_sys2::EVP_PKEY_CTX_get0_pkey(ctx))?;
		let private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private> = foreign_types_shared::ForeignTypeRef::from_ptr(private_key);
		let rsa = private_key.rsa()?;
		let crate::ex_data::KeyExData { .. } =
			if let Ok(ex_data) = crate::ex_data::get(&*foreign_types_shared::ForeignType::as_ptr(&rsa)) {
				ex_data
			}
			else {
				let openssl_rsa_sign = OPENSSL_EVP_RSA_SIGN.expect("OPENSSL_EVP_RSA_SIGN must have been set by get_evp_rsa_method earlier");
				match openssl_rsa_sign(ctx, sig, siglen, tbs, tbslen) {
					result if result <= 0 => return Err(format!("OPENSSL_EVP_RSA_SIGN returned {}", result).into()),
					_ => return Ok(()),
				}
			};

		let mut padding = 0;
		openssl2::openssl_returns_positive(openssl_sys::EVP_PKEY_CTX_get_rsa_padding(ctx, &mut padding))?;

		// Let openssl handle other schemes, and use the key's encrypt function (aziot_key__rsa_method_priv_enc) as necessary.

		let openssl_evp_rsa_sign = OPENSSL_EVP_RSA_SIGN.expect("OPENSSL_EVP_RSA_SIGN was never set");
		let result = openssl_evp_rsa_sign(ctx, sig, siglen, tbs, tbslen);
		if result > 0 {
			Ok(())
		}
		else {
			Err(format!("openssl_evp_rsa_sign failed with {}", result).into())
		}
	});
	match result {
		Ok(()) => 1,
		Err(()) => -1,
	}
}

pub(super) unsafe fn aziot_key_rsa_method() -> *const openssl_sys::RSA_METHOD {
	static mut RESULT: *const openssl_sys::RSA_METHOD = std::ptr::null();
	static RESULT_INIT: std::sync::Once = std::sync::Once::new();

	RESULT_INIT.call_once(|| {
		let openssl_rsa_method = openssl_sys2::RSA_get_default_method();
		let aziot_key_rsa_method = openssl_sys2::RSA_meth_dup(openssl_rsa_method);

		openssl_sys2::RSA_meth_set_flags(aziot_key_rsa_method, 0);

		// Don't override openssl's RSA signing function (via RSA_meth_set_sign).
		// Let it compute the digest, and only override the final step to encrypt that digest.
		openssl_sys2::RSA_meth_set_priv_enc(aziot_key_rsa_method, aziot_key_rsa_method_priv_enc);

		openssl_sys2::RSA_meth_set_priv_dec(aziot_key_rsa_method, aziot_key_rsa_method_priv_dec);

		RESULT = aziot_key_rsa_method as _;
	});

	RESULT
}

unsafe extern "C" fn aziot_key_rsa_method_priv_enc(
	flen: std::os::raw::c_int,
	from: *const std::os::raw::c_uchar,
	to: *mut std::os::raw::c_uchar,
	rsa: *mut openssl_sys::RSA,
	padding: std::os::raw::c_int,
) -> std::os::raw::c_int {
	let result = super::r#catch(Some(|| super::Error::AZIOT_KEY_RSA_PRIV_ENC), || {
		let crate::ex_data::KeyExData { client, handle } = crate::ex_data::get(&*rsa)?;

		let mechanism = match padding {
			openssl_sys::RSA_PKCS1_PADDING => aziot_key_common::EncryptMechanism::RsaPkcs1,
			padding => return Err(format!("unrecognized RSA padding scheme 0x{:08x}", padding).into()),
		};

		let digest = std::slice::from_raw_parts(from, std::convert::TryInto::try_into(flen).expect("c_int -> usize"));

		let signature = client.encrypt(handle, mechanism, digest)?;
		let signature_len = signature.len();
		{
			let max_signature_len = {
				let rsa: &openssl::rsa::RsaRef<openssl::pkey::Private> = foreign_types_shared::ForeignTypeRef::from_ptr(rsa);
				std::convert::TryInto::try_into(rsa.size()).expect("c_int -> usize")
			};
			if signature_len > max_signature_len {
				return Err(format!("openssl expected signature of length <= {} but ks returned a signature of length {}", max_signature_len, signature_len).into());
			}
		}

		// openssl requires that `to` has space for `RSA_size(rsa)` bytes. Trust the caller.
		let signature_out = std::slice::from_raw_parts_mut(to, std::convert::TryInto::try_into(signature_len).expect("c_int -> usize"));
		signature_out[..signature_len].copy_from_slice(&signature);

		let signature_len = std::convert::TryInto::try_into(signature_len).expect("usize -> c_int");

		Ok(signature_len)
	});
	match result {
		Ok(signature_len) => signature_len,
		Err(()) => -1,
	}
}

unsafe extern "C" fn aziot_key_rsa_method_priv_dec(
	_flen: std::os::raw::c_int,
	_from: *const std::os::raw::c_uchar,
	_to: *mut std::os::raw::c_uchar,
	_rsa: *mut openssl_sys::RSA,
	_padding: std::os::raw::c_int,
) -> std::os::raw::c_int {
	// TODO

	-1
}
