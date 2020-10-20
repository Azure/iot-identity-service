// Copyright (c) Microsoft. All rights reserved.

//! `ecdsa.h`

#[cfg(not(ossl110))]
#[repr(C)]
pub struct ECDSA_METHOD([u8; 0]);

#[cfg(not(ossl110))]
extern "C" {
    pub fn ECDSA_size(eckey: *const openssl_sys::EC_KEY) -> std::os::raw::c_int;

    pub fn ECDSA_get_ex_data(
        d: *const openssl_sys::EC_KEY,
        idx: std::os::raw::c_int,
    ) -> *mut std::ffi::c_void;
    pub fn ECDSA_set_ex_data(
        d: *mut openssl_sys::EC_KEY,
        idx: std::os::raw::c_int,
        arg: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int;

    pub fn ECDSA_set_method(
        key: *mut openssl_sys::EC_KEY,
        meth: *const ECDSA_METHOD,
    ) -> std::os::raw::c_int;

    pub fn ECDSA_OpenSSL() -> *const ECDSA_METHOD;

    pub fn ECDSA_METHOD_new(ecdsa_method: *const ECDSA_METHOD) -> *mut ECDSA_METHOD;

    pub fn ECDSA_METHOD_set_sign(
        ecdsa_method: *mut ECDSA_METHOD,
        ecdsa_do_sign: Option<
            unsafe extern "C" fn(
                dgst: *const std::os::raw::c_uchar,
                dgst_len: std::os::raw::c_int,
                inv: *const openssl_sys::BIGNUM,
                rp: *const openssl_sys::BIGNUM,
                eckey: *mut openssl_sys::EC_KEY,
            ) -> *mut openssl_sys::ECDSA_SIG,
        >,
    );
}
