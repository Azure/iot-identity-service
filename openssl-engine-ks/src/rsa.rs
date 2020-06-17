use ks_common::KeysServiceInterface;

impl crate::ex_data::HasExData<crate::ex_data::KeyExData> for openssl_sys::RSA {
	unsafe fn index() -> openssl::ex_data::Index<Self, crate::ex_data::KeyExData> {
		crate::ex_data::ex_indices().rsa
	}
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn ks_dupf_rsa_ex_data(
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
unsafe extern "C" fn ks_freef_rsa_ex_data(
	_parent: *mut std::ffi::c_void,
	ptr: *mut std::ffi::c_void,
	_ad: *mut openssl_sys::CRYPTO_EX_DATA,
	idx: std::os::raw::c_int,
	_argl: std::os::raw::c_long,
	_argp: *mut std::ffi::c_void,
) {
	crate::ex_data::free::<openssl_sys::RSA, crate::ex_data::KeyExData>(ptr, idx);
}

static mut OPENSSL_RSA_SIGN: Option<unsafe extern "C" fn (
	ctx: *mut openssl_sys::EVP_PKEY_CTX,
	sig: *mut std::os::raw::c_uchar,
	siglen: *mut usize,
	tbs: *const std::os::raw::c_uchar,
	tbslen: usize,
) -> std::os::raw::c_int> = None;

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
	openssl_sys2::EVP_PKEY_meth_get_sign(openssl_method, &mut openssl_rsa_sign_init, &mut OPENSSL_RSA_SIGN);
	openssl_sys2::EVP_PKEY_meth_set_sign(result, openssl_rsa_sign_init, Some(evp_rsa_sign));

	Ok(result)
}

unsafe extern "C" fn evp_rsa_sign(
	ctx: *mut openssl_sys::EVP_PKEY_CTX,
	sig: *mut std::os::raw::c_uchar,
	siglen: *mut usize,
	tbs: *const std::os::raw::c_uchar,
	tbslen: usize,
) -> std::os::raw::c_int {
	let result = super::r#catch(Some(|| super::Error::KS_RSA_SIGN), || {
		let private_key = openssl2::openssl_returns_nonnull(openssl_sys2::EVP_PKEY_CTX_get0_pkey(ctx))?;
		let private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private> = foreign_types_shared::ForeignTypeRef::from_ptr(private_key);
		let rsa = private_key.rsa()?;
		let crate::ex_data::KeyExData { client, handle } =
			if let Ok(ex_data) = crate::ex_data::get(&*foreign_types_shared::ForeignType::as_ptr(&rsa)) {
				ex_data
			}
			else {
				let openssl_rsa_sign = OPENSSL_RSA_SIGN.expect("OPENSSL_RSA_SIGN must have been set by get_evp_rsa_method earlier");
				match openssl_rsa_sign(ctx, sig, siglen, tbs, tbslen) {
					result if result <= 0 => return Err(format!("OPENSSL_RSA_SIGN returned {}", result).into()),
					_ => return Ok(()),
				}
			};

		let mut padding = 0;
		openssl2::openssl_returns_positive(openssl_sys::EVP_PKEY_CTX_get_rsa_padding(ctx, &mut padding))?;

		let mechanism = match padding {
			openssl_sys::RSA_PKCS1_PADDING => {
				let mut signature_md = std::ptr::null();
				openssl2::openssl_returns_positive(openssl_sys2::EVP_PKEY_CTX_get_signature_md_f(ctx, &mut signature_md))?;
				let message_digest = match openssl_sys::EVP_MD_type(signature_md) {
					openssl_sys::NID_sha1 => ks_common::RsaPkcs1MessageDigest::Sha1,
					openssl_sys::NID_sha224 => ks_common::RsaPkcs1MessageDigest::Sha224,
					openssl_sys::NID_sha256 => ks_common::RsaPkcs1MessageDigest::Sha256,
					openssl_sys::NID_sha384 => ks_common::RsaPkcs1MessageDigest::Sha384,
					openssl_sys::NID_sha512 => ks_common::RsaPkcs1MessageDigest::Sha512,
					nid => return Err(format!("unrecognized signature_md nid 0x{:08x}", nid).into()),
				};
				ks_common::SignMechanism::RsaPkcs1 { message_digest }
			},

			// openssl_sys::RSA_PKCS1_PSS_PADDING => {
			// 	let message_digest = match openssl_sys::EVP_MD_type(signature_md) {
			// 		openssl_sys::NID_sha1 => ks_common::SignMessageDigest::Sha1,
			// 		openssl_sys::NID_sha224 => ks_common::SignMessageDigest::Sha224,
			// 		openssl_sys::NID_sha256 => ks_common::SignMessageDigest::Sha256,
			// 		openssl_sys::NID_sha384 => ks_common::SignMessageDigest::Sha384,
			// 		openssl_sys::NID_sha512 => ks_common::SignMessageDigest::Sha512,
			// 		nid => return Err(format!("unrecognized signature_md nid 0x{:08x}", nid).into()),
			// 	};

			// 	let mut rsa_mgf1_md = std::ptr::null();
			// 	openssl2::openssl_returns_positive(openssl_sys2::EVP_PKEY_CTX_get_rsa_mgf1_md_f(ctx, &mut rsa_mgf1_md))?;

			// 	let mut rsa_pss_salt_len = 0;
			// 	openssl2::openssl_returns_positive(openssl_sys2::EVP_PKEY_CTX_get_rsa_pss_saltlen_f(ctx, &mut rsa_pss_salt_len))?;

			// 	let rsa_pss_salt_len = match rsa_pss_salt_len {
			// 		rsa_pss_salt_len if rsa_pss_salt_len > 0 => rsa_pss_salt_len,
			// 		-1 => openssl_sys::EVP_MD_size(signature_md),
			// 		rsa_pss_salt_len => return Err(format!("invalid rsa_pss_salt_len 0x{:08x}", rsa_pss_salt_len).into()),
			// 	};

			// 	(ks_common::SignMechanism::RsaPss {
			// 		mask_generation_function: match openssl_sys::EVP_MD_type(rsa_mgf1_md) {
			// 			openssl_sys::NID_sha1 => ks_common::RsaPssMaskGenerationFunction::Sha1,
			// 			openssl_sys::NID_sha224 => ks_common::RsaPssMaskGenerationFunction::Sha224,
			// 			openssl_sys::NID_sha256 => ks_common::RsaPssMaskGenerationFunction::Sha256,
			// 			openssl_sys::NID_sha384 => ks_common::RsaPssMaskGenerationFunction::Sha384,
			// 			openssl_sys::NID_sha512 => ks_common::RsaPssMaskGenerationFunction::Sha512,
			// 			nid => return Err(format!("unrecognized rsa_mgf1_md nid 0x{:08x}", nid).into()),
			// 		},

			// 		salt_len: std::convert::TryInto::try_into(rsa_pss_salt_len).expect("c_int -> CK_ULONG"),
			// 	}, message_digest)
			// },

			padding => return Err(format!("unexpected padding {}", padding).into()),
		};

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
