// Copyright (c) Microsoft. All rights reserved.

//! `ec.h`

#[cfg(ossl110)]
#[repr(C)]
pub struct EC_KEY_METHOD([u8; 0]);

#[cfg(ossl110)]
extern "C" {
    pub fn ECDSA_size(eckey: *const openssl_sys::EC_KEY) -> std::os::raw::c_int;

    pub fn EC_KEY_get_ex_data(
        key: *const openssl_sys::EC_KEY,
        idx: std::os::raw::c_int,
    ) -> *mut std::ffi::c_void;
    pub fn EC_KEY_set_ex_data(
        key: *mut openssl_sys::EC_KEY,
        idx: std::os::raw::c_int,
        arg: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int;

    pub fn EC_KEY_get_method(key: *const openssl_sys::EC_KEY) -> *const EC_KEY_METHOD;
    pub fn EC_KEY_set_method(
        key: *mut openssl_sys::EC_KEY,
        meth: *const EC_KEY_METHOD,
    ) -> std::os::raw::c_int;

    pub fn EC_KEY_OpenSSL() -> *const EC_KEY_METHOD;

    pub fn EC_KEY_METHOD_new(meth: *const EC_KEY_METHOD) -> *mut EC_KEY_METHOD;

    pub fn EC_KEY_METHOD_get_sign(
        meth: *const EC_KEY_METHOD,
        psign: *mut Option<
            unsafe extern "C" fn(
                r#type: std::os::raw::c_int,
                dgst: *const std::os::raw::c_uchar,
                dlen: std::os::raw::c_int,
                sig: *mut std::os::raw::c_uchar,
                siglen: *mut std::os::raw::c_uint,
                kinv: *const openssl_sys::BIGNUM,
                r: *const openssl_sys::BIGNUM,
                eckey: *mut openssl_sys::EC_KEY,
            ) -> std::os::raw::c_int,
        >,
        psign_setup: *mut Option<
            unsafe extern "C" fn(
                eckey: *mut openssl_sys::EC_KEY,
                ctx_in: *mut openssl_sys::BN_CTX,
                kinvp: *mut *mut openssl_sys::BIGNUM,
                rp: *mut *mut openssl_sys::BIGNUM,
            ) -> std::os::raw::c_int,
        >,
        psign_sig: *mut Option<
            unsafe extern "C" fn(
                dgst: *const std::os::raw::c_uchar,
                dlen: std::os::raw::c_int,
                kinv: *const openssl_sys::BIGNUM,
                r: *const openssl_sys::BIGNUM,
                eckey: *mut openssl_sys::EC_KEY,
            ) -> *mut openssl_sys::ECDSA_SIG,
        >,
    );
    pub fn EC_KEY_METHOD_set_sign(
        meth: *mut EC_KEY_METHOD,
        sign: Option<
            unsafe extern "C" fn(
                r#type: std::os::raw::c_int,
                dgst: *const std::os::raw::c_uchar,
                dlen: std::os::raw::c_int,
                sig: *mut std::os::raw::c_uchar,
                siglen: *mut std::os::raw::c_uint,
                kinv: *const openssl_sys::BIGNUM,
                r: *const openssl_sys::BIGNUM,
                eckey: *mut openssl_sys::EC_KEY,
            ) -> std::os::raw::c_int,
        >,
        sign_setup: Option<
            unsafe extern "C" fn(
                eckey: *mut openssl_sys::EC_KEY,
                ctx_in: *mut openssl_sys::BN_CTX,
                kinvp: *mut *mut openssl_sys::BIGNUM,
                rp: *mut *mut openssl_sys::BIGNUM,
            ) -> std::os::raw::c_int,
        >,
        sign_sig: Option<
            unsafe extern "C" fn(
                dgst: *const std::os::raw::c_uchar,
                dlen: std::os::raw::c_int,
                kinv: *const openssl_sys::BIGNUM,
                r: *const openssl_sys::BIGNUM,
                eckey: *mut openssl_sys::EC_KEY,
            ) -> *mut openssl_sys::ECDSA_SIG,
        >,
    );
}
