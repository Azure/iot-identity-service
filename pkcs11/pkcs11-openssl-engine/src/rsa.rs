impl crate::ex_data::HasExData<pkcs11::Object<openssl::rsa::Rsa<openssl::pkey::Private>>> for openssl_sys::RSA {
	unsafe fn index() -> openssl::ex_data::Index<Self, pkcs11::Object<openssl::rsa::Rsa<openssl::pkey::Private>>> {
		crate::ex_data::ex_indices().rsa
	}
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn pkcs11_dupf_rsa_ex_data(
	_to: *mut openssl_sys::CRYPTO_EX_DATA,
	_from: *const openssl_sys::CRYPTO_EX_DATA,
	from_d: *mut std::ffi::c_void,
	idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
	crate::ex_data::dup::<openssl_sys::RSA, pkcs11::Object<openssl::rsa::Rsa<openssl::pkey::Private>>>(from_d, idx);
	1
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn pkcs11_freef_rsa_ex_data(
	_parent: *mut std::ffi::c_void,
	ptr: *mut std::ffi::c_void,
	_ad: *mut openssl_sys::CRYPTO_EX_DATA,
	idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) {
	crate::ex_data::free::<openssl_sys::RSA, pkcs11::Object<openssl::rsa::Rsa<openssl::pkey::Private>>>(ptr, idx);
}

#[cfg(ossl110)]
static mut OPENSSL_EVP_RSA_SIGN: Option<unsafe extern "C" fn(
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
	// So we want to override the method, detect that we're doing PSS signing, and directly invoke the PKCS#11 sign operation
	// with the CKM_RSA_PKCS_PSS mechanism instead.

	let openssl_method = openssl2::openssl_returns_nonnull_const(openssl_sys2::EVP_PKEY_meth_find(openssl_sys::EVP_PKEY_RSA))?;
	let result =
		openssl2::openssl_returns_nonnull(
			openssl_sys2::EVP_PKEY_meth_new(openssl_sys::EVP_PKEY_RSA, openssl_sys2::EVP_PKEY_FLAG_AUTOARGLEN))?;
	openssl_sys2::EVP_PKEY_meth_copy(result, openssl_method);

	let mut openssl_rsa_sign_init = None;
	openssl_sys2::EVP_PKEY_meth_get_sign(openssl_method, &mut openssl_rsa_sign_init, &mut OPENSSL_EVP_RSA_SIGN);
	openssl_sys2::EVP_PKEY_meth_set_sign(result, openssl_rsa_sign_init, Some(pkcs11_evp_rsa_sign));

	Ok(result)
}

#[cfg(ossl110)]
unsafe extern "C" fn pkcs11_evp_rsa_sign(
	ctx: *mut openssl_sys::EVP_PKEY_CTX,
	sig: *mut std::os::raw::c_uchar,
	siglen: *mut usize,
	tbs: *const std::os::raw::c_uchar,
	tbslen: usize,
) -> std::os::raw::c_int {
	let result = super::r#catch(Some(|| super::Error::PKCS11_RSA_SIGN), || {
		let private_key = openssl2::openssl_returns_nonnull(openssl_sys2::EVP_PKEY_CTX_get0_pkey(ctx))?;
		let private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private> = foreign_types_shared::ForeignTypeRef::from_ptr(private_key);
		let rsa = private_key.rsa()?;
		let object_handle =
			if let Ok(object_handle) = crate::ex_data::get(&*foreign_types_shared::ForeignType::as_ptr(&rsa)) {
				object_handle
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

		if padding == openssl_sys::RSA_PKCS1_PSS_PADDING {
			let mut signature_md = std::ptr::null();
			openssl2::openssl_returns_positive(openssl_sys2::EVP_PKEY_CTX_get_signature_md_f(ctx, &mut signature_md))?;

			let mut rsa_mgf1_md = std::ptr::null();
			openssl2::openssl_returns_positive(openssl_sys2::EVP_PKEY_CTX_get_rsa_mgf1_md_f(ctx, &mut rsa_mgf1_md))?;

			let mut rsa_pss_salt_len = 0;
			openssl2::openssl_returns_positive(openssl_sys2::EVP_PKEY_CTX_get_rsa_pss_saltlen_f(ctx, &mut rsa_pss_salt_len))?;

			let rsa_pss_salt_len = match rsa_pss_salt_len {
				rsa_pss_salt_len if rsa_pss_salt_len > 0 => rsa_pss_salt_len,
				-1 => openssl_sys::EVP_MD_size(signature_md),
				rsa_pss_salt_len => return Err(format!("invalid rsa_pss_salt_len 0x{:08x}", rsa_pss_salt_len).into()),
			};

			let mechanism = pkcs11::RsaSignMechanism::Pss(pkcs11_sys::CK_RSA_PKCS_PSS_PARAMS {
				hashAlg: match openssl_sys::EVP_MD_type(signature_md) {
					openssl_sys::NID_sha1 => pkcs11_sys::CKM_SHA_1,
					openssl_sys::NID_sha224 => pkcs11_sys::CKM_SHA224,
					openssl_sys::NID_sha256 => pkcs11_sys::CKM_SHA256,
					openssl_sys::NID_sha384 => pkcs11_sys::CKM_SHA384,
					openssl_sys::NID_sha512 => pkcs11_sys::CKM_SHA512,
					nid => return Err(format!("unrecognized signature_md nid 0x{:08x}", nid).into()),
				},

				mgf: match openssl_sys::EVP_MD_type(rsa_mgf1_md) {
					openssl_sys::NID_sha1 => pkcs11_sys::CKG_MGF1_SHA1,
					openssl_sys::NID_sha224 => pkcs11_sys::CKG_MGF1_SHA224,
					openssl_sys::NID_sha256 => pkcs11_sys::CKG_MGF1_SHA256,
					openssl_sys::NID_sha384 => pkcs11_sys::CKG_MGF1_SHA384,
					openssl_sys::NID_sha512 => pkcs11_sys::CKG_MGF1_SHA512,
					nid => return Err(format!("unrecognized rsa_mgf1_md nid 0x{:08x}", nid).into()),
				},

				sLen: std::convert::TryInto::try_into(rsa_pss_salt_len).expect("c_int -> CK_ULONG"),
			});

			let digest = std::slice::from_raw_parts(tbs, std::convert::TryInto::try_into(tbslen).expect("c_int -> usize"));

			let mut signature = std::slice::from_raw_parts_mut(sig, std::convert::TryInto::try_into(*siglen).expect("c_int -> usize"));

			let signature_len = object_handle.sign(&mechanism, digest, &mut signature)?;
			let signature_len = std::convert::TryInto::try_into(signature_len).expect("CK_ULONG -> c_int");
			*siglen = signature_len;

			Ok(())
		}
		else {
			// Let openssl handle other schemes, and use the key's encrypt function (pkcs11_rsa_method_priv_enc) as necessary.

			let openssl_evp_rsa_sign = OPENSSL_EVP_RSA_SIGN.expect("OPENSSL_EVP_RSA_SIGN was never set");
			let result = openssl_evp_rsa_sign(ctx, sig, siglen, tbs, tbslen);
			if result > 0 {
				Ok(())
			}
			else {
				Err(format!("openssl_evp_rsa_sign failed with {}", result).into())
			}
		}
	});
	match result {
		Ok(()) => 1,
		Err(()) => -1,
	}
}

pub(super) unsafe fn pkcs11_rsa_method() -> *const openssl_sys::RSA_METHOD {
	static mut RESULT: *const openssl_sys::RSA_METHOD = std::ptr::null();
	static RESULT_INIT: std::sync::Once = std::sync::Once::new();

	RESULT_INIT.call_once(|| {
		let openssl_rsa_method = openssl_sys2::RSA_get_default_method();
		let pkcs11_rsa_method = openssl_sys2::RSA_meth_dup(openssl_rsa_method);

		openssl_sys2::RSA_meth_set_flags(pkcs11_rsa_method, 0);

		// Don't override openssl's RSA signing function (via RSA_meth_set_sign).
		// Let it compute the digest, and only override the final step to encrypt that digest.
		openssl_sys2::RSA_meth_set_priv_enc(pkcs11_rsa_method, pkcs11_rsa_method_priv_enc);

		openssl_sys2::RSA_meth_set_priv_dec(pkcs11_rsa_method, pkcs11_rsa_method_priv_dec);

		RESULT = pkcs11_rsa_method as _;
	});

	RESULT
}

unsafe extern "C" fn pkcs11_rsa_method_priv_enc(
	flen: std::os::raw::c_int,
	from: *const std::os::raw::c_uchar,
	to: *mut std::os::raw::c_uchar,
	rsa: *mut openssl_sys::RSA,
	padding: std::os::raw::c_int,
) -> std::os::raw::c_int {
	let result = super::r#catch(Some(|| super::Error::PKCS11_RSA_PRIV_ENC), || {
		let object_handle = crate::ex_data::get(&*rsa)?;

		let mechanism = match padding {
			openssl_sys::RSA_PKCS1_PADDING => pkcs11::RsaSignMechanism::Pkcs1,
			padding => return Err(format!("unrecognized RSA padding scheme 0x{:08x}", padding).into()),
		};

		let digest = std::slice::from_raw_parts(from, std::convert::TryInto::try_into(flen).expect("c_int -> usize"));

		// openssl requires that `to` has space for `RSA_size(rsa)` bytes. Trust the caller.
		let signature_len = {
			let rsa: &openssl::rsa::RsaRef<openssl::pkey::Private> = foreign_types_shared::ForeignTypeRef::from_ptr(rsa);
			rsa.size()
		};
		let mut signature = std::slice::from_raw_parts_mut(to, std::convert::TryInto::try_into(signature_len).expect("c_int -> usize"));

		let signature_len = object_handle.sign(&mechanism, digest, &mut signature)?;
		let signature_len = std::convert::TryInto::try_into(signature_len).expect("CK_ULONG -> c_int");

		Ok(signature_len)
	});
	match result {
		Ok(signature_len) => signature_len,
		Err(()) => -1,
	}
}

unsafe extern "C" fn pkcs11_rsa_method_priv_dec(
	_flen: std::os::raw::c_int,
	_from: *const std::os::raw::c_uchar,
	_to: *mut std::os::raw::c_uchar,
	_rsa: *mut openssl_sys::RSA,
	_padding: std::os::raw::c_int,
) -> std::os::raw::c_int {
	// TODO

	-1
}
