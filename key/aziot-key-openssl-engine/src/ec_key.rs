// Copyright (c) Microsoft. All rights reserved.

impl crate::ex_data::HasExData<crate::ex_data::KeyExData> for openssl_sys::EC_KEY {
    unsafe fn index() -> openssl::ex_data::Index<Self, crate::ex_data::KeyExData> {
        crate::ex_data::ex_indices().ec_key
    }
}

#[no_mangle]
#[allow(clippy::similar_names)]
unsafe extern "C" fn aziot_key_dupf_ec_key_ex_data(
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
unsafe extern "C" fn aziot_key_freef_ec_key_ex_data(
    _parent: *mut std::ffi::c_void,
    ptr: *mut std::ffi::c_void,
    _ad: *mut openssl_sys::CRYPTO_EX_DATA,
    idx: std::os::raw::c_int,
    _argl: std::os::raw::c_long,
    _argp: *mut std::ffi::c_void,
) {
    crate::ex_data::free::<openssl_sys::EC_KEY, crate::ex_data::KeyExData>(ptr, idx);
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
pub(super) unsafe fn aziot_key_ec_key_method() -> *const openssl_sys2::EC_KEY_METHOD {
    static mut RESULT: *const openssl_sys2::EC_KEY_METHOD = std::ptr::null();
    static RESULT_INIT: std::sync::Once = std::sync::Once::new();

    RESULT_INIT.call_once(|| {
        let openssl_ec_key_method = openssl_sys2::EC_KEY_OpenSSL();
        let aziot_key_ec_key_method = openssl_sys2::EC_KEY_METHOD_new(openssl_ec_key_method);

        let mut openssl_ec_key_sign = None;
        openssl_sys2::EC_KEY_METHOD_get_sign(
            aziot_key_ec_key_method,
            &mut openssl_ec_key_sign,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
        openssl_sys2::EC_KEY_METHOD_set_sign(
            aziot_key_ec_key_method,
            openssl_ec_key_sign, // Reuse openssl's function to compute the digest
            None, // Disable sign_setup because aziot_key_ec_key_sign_sig doesn't need the pre-computed kinv and rp
            Some(aziot_key_ec_key_sign_sig),
        );

        RESULT = aziot_key_ec_key_method as _;
    });

    RESULT
}

#[cfg(not(ossl110))]
pub(super) unsafe fn aziot_key_ec_key_method() -> *const openssl_sys2::ECDSA_METHOD {
    static mut RESULT: *const openssl_sys2::ECDSA_METHOD = std::ptr::null();
    static RESULT_INIT: std::sync::Once = std::sync::Once::new();

    RESULT_INIT.call_once(|| {
        let openssl_ec_key_method = openssl_sys2::ECDSA_OpenSSL();
        let aziot_key_ec_key_method = openssl_sys2::ECDSA_METHOD_new(openssl_ec_key_method);

        openssl_sys2::ECDSA_METHOD_set_sign(
            aziot_key_ec_key_method,
            Some(aziot_key_ec_key_sign_sig),
        );

        RESULT = aziot_key_ec_key_method as _;
    });

    RESULT
}

unsafe extern "C" fn aziot_key_ec_key_sign_sig(
    dgst: *const std::os::raw::c_uchar,
    dlen: std::os::raw::c_int,
    _kinv: *const openssl_sys::BIGNUM,
    _r: *const openssl_sys::BIGNUM,
    eckey: *mut openssl_sys::EC_KEY,
) -> *mut openssl_sys::ECDSA_SIG {
    let result = super::r#catch(Some(|| super::Error::AZIOT_KEY_EC_SIGN), || {
        let crate::ex_data::KeyExData { client, handle } = crate::ex_data::get(&*eckey)?;

        let mechanism = aziot_key_common::SignMechanism::Ecdsa;

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

        let signature = client.sign(handle, mechanism, digest)?;
        let signature = openssl::ecdsa::EcdsaSig::from_der(&signature)?;

        let result = openssl2::foreign_type_into_ptr(signature);

        Ok(result)
    });
    match result {
        Ok(signature) => signature,
        Err(()) => std::ptr::null_mut(),
    }
}
