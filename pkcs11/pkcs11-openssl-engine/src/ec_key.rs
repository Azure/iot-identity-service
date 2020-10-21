// Copyright (c) Microsoft. All rights reserved.

impl crate::ex_data::HasExData<pkcs11::Object<openssl::ec::EcKey<openssl::pkey::Private>>>
    for openssl_sys::EC_KEY
{
    unsafe fn index(
    ) -> openssl::ex_data::Index<Self, pkcs11::Object<openssl::ec::EcKey<openssl::pkey::Private>>>
    {
        crate::ex_data::ex_indices().ec_key
    }
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn pkcs11_dupf_ec_key_ex_data(
    _to: *mut openssl_sys::CRYPTO_EX_DATA,
    _from: *const openssl_sys::CRYPTO_EX_DATA,
    from_d: *mut std::ffi::c_void,
    idx: std::os::raw::c_int,
    _argl: std::os::raw::c_long,
    _argp: *mut std::ffi::c_void,
) -> std::os::raw::c_int {
    crate::ex_data::dup::<
        openssl_sys::EC_KEY,
        pkcs11::Object<openssl::ec::EcKey<openssl::pkey::Private>>,
    >(from_d, idx);
    1
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn pkcs11_freef_ec_key_ex_data(
    _parent: *mut std::ffi::c_void,
    ptr: *mut std::ffi::c_void,
    _ad: *mut openssl_sys::CRYPTO_EX_DATA,
    idx: std::os::raw::c_int,
    _argl: std::os::raw::c_long,
    _argp: *mut std::ffi::c_void,
) {
    crate::ex_data::free::<
        openssl_sys::EC_KEY,
        pkcs11::Object<openssl::ec::EcKey<openssl::pkey::Private>>,
    >(ptr, idx);
}

#[cfg(ossl110)]
pub(super) unsafe fn get_evp_ec_method(
) -> Result<*const openssl_sys2::EVP_PKEY_METHOD, openssl2::Error> {
    // The default EC method is good enough.

    let openssl_method = openssl2::openssl_returns_nonnull_const(
        openssl_sys2::EVP_PKEY_meth_find(openssl_sys::EVP_PKEY_EC),
    )?;
    let result = openssl2::openssl_returns_nonnull(openssl_sys2::EVP_PKEY_meth_new(
        openssl_sys::EVP_PKEY_EC,
        openssl_sys2::EVP_PKEY_FLAG_AUTOARGLEN,
    ))?;
    openssl_sys2::EVP_PKEY_meth_copy(result, openssl_method);

    Ok(result)
}

#[cfg(ossl110)]
pub(super) unsafe fn pkcs11_ec_key_method() -> *const openssl_sys2::EC_KEY_METHOD {
    static mut RESULT: *const openssl_sys2::EC_KEY_METHOD = std::ptr::null();
    static RESULT_INIT: std::sync::Once = std::sync::Once::new();

    RESULT_INIT.call_once(|| {
        let openssl_ec_key_method = openssl_sys2::EC_KEY_OpenSSL();
        let pkcs11_ec_key_method = openssl_sys2::EC_KEY_METHOD_new(openssl_ec_key_method);

        let mut openssl_ec_key_sign = None;
        openssl_sys2::EC_KEY_METHOD_get_sign(
            pkcs11_ec_key_method,
            &mut openssl_ec_key_sign,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        openssl_sys2::EC_KEY_METHOD_set_sign(
            pkcs11_ec_key_method,
            openssl_ec_key_sign, // Reuse openssl's function to compute the digest
            None, // Disable sign_setup because pkcs11_ec_key_sign_sig doesn't need the pre-computed kinv and rp
            Some(pkcs11_ec_key_sign_sig),
        );

        RESULT = pkcs11_ec_key_method as _;
    });

    RESULT
}

#[cfg(not(ossl110))]
pub(super) unsafe fn pkcs11_ec_key_method() -> *const openssl_sys2::ECDSA_METHOD {
    static mut RESULT: *const openssl_sys2::ECDSA_METHOD = std::ptr::null();
    static RESULT_INIT: std::sync::Once = std::sync::Once::new();

    RESULT_INIT.call_once(|| {
        let openssl_ec_key_method = openssl_sys2::ECDSA_OpenSSL();
        let pkcs11_ec_key_method = openssl_sys2::ECDSA_METHOD_new(openssl_ec_key_method);

        openssl_sys2::ECDSA_METHOD_set_sign(pkcs11_ec_key_method, Some(pkcs11_ec_key_sign_sig));

        RESULT = pkcs11_ec_key_method as _;
    });

    RESULT
}

unsafe extern "C" fn pkcs11_ec_key_sign_sig(
    dgst: *const std::os::raw::c_uchar,
    dlen: std::os::raw::c_int,
    _kinv: *const openssl_sys::BIGNUM,
    _r: *const openssl_sys::BIGNUM,
    eckey: *mut openssl_sys::EC_KEY,
) -> *mut openssl_sys::ECDSA_SIG {
    let result = super::r#catch(Some(|| super::Error::PKCS11_EC_SIGN), || {
        let object_handle = crate::ex_data::get(&*eckey)?;

        // Truncate dgst if it's longer than the key order length. Eg The digest input for a P-256 key can only be 32 bytes.
        //
        // softhsm does this inside its C_Sign impl, but tpm2-pkcs11 does not, and the PKCS#11 spec does not opine on the matter.
        // So we need to truncate the digest ourselves.
        let dlen = {
            let eckey: &openssl::ec::EcKeyRef<openssl::pkey::Private> =
                foreign_types_shared::ForeignTypeRef::from_ptr(eckey);
            let group = eckey.group();
            let mut order = openssl::bn::BigNum::new()?;
            let mut big_num_context = openssl::bn::BigNumContext::new()?;
            group.order(&mut order, &mut big_num_context)?;
            let order_num_bits = order.num_bits();
            if dlen.saturating_mul(8) > order_num_bits {
                let new_dlen = (order_num_bits + 7) / 8;

                // The original `dlen` was at least `order_num_bits / 8 + 1`. `new_dlen` is at most `order_num_bits / 8 + 1`.
                // So this assert should always hold.
                assert!(dlen >= new_dlen);

                new_dlen
            } else {
                dlen
            }
        };

        let digest = std::slice::from_raw_parts(
            dgst,
            std::convert::TryInto::try_into(dlen).expect("c_int -> usize"),
        );

        let signature_len = openssl_sys2::ECDSA_size(eckey);

        let mut signature =
            vec![0_u8; std::convert::TryInto::try_into(signature_len).expect("c_int -> usize")];
        let signature_len = object_handle.sign(digest, &mut signature)?;
        let signature_len: usize =
            std::convert::TryInto::try_into(signature_len).expect("CK_ULONG -> usize");
        let r = openssl::bn::BigNum::from_slice(&signature[..(signature_len / 2)])?;
        let s = openssl::bn::BigNum::from_slice(&signature[(signature_len / 2)..signature_len])?;
        let signature = openssl::ecdsa::EcdsaSig::from_private_components(r, s)?;

        let result = openssl2::foreign_type_into_ptr(signature);

        Ok(result)
    });
    match result {
        Ok(signature) => signature,
        Err(()) => std::ptr::null_mut(),
    }
}
