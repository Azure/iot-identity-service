// Copyright (c) Microsoft. All rights reserved.

//! `rsa.h`

extern "C" {
    pub fn RSA_get_ex_data(
        r: *const openssl_sys::RSA,
        idx: std::os::raw::c_int,
    ) -> *mut std::ffi::c_void;
    pub fn RSA_set_ex_data(
        r: *mut openssl_sys::RSA,
        idx: std::os::raw::c_int,
        arg: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int;

    pub fn RSA_get_method(rsa: *const openssl_sys::RSA) -> *const openssl_sys::RSA_METHOD;
    pub fn RSA_set_method(
        rsa: *mut openssl_sys::RSA,
        meth: *const openssl_sys::RSA_METHOD,
    ) -> std::os::raw::c_int;

    pub fn RSA_get_default_method() -> *const openssl_sys::RSA_METHOD;
}

extern "C" {
    pub fn RSA_meth_dup(meth: *const openssl_sys::RSA_METHOD) -> *mut openssl_sys::RSA_METHOD;
    pub fn RSA_meth_set_flags(
        meth: *mut openssl_sys::RSA_METHOD,
        flags: std::os::raw::c_int,
    ) -> std::os::raw::c_int;
    pub fn RSA_meth_set_priv_enc(
        rsa: *mut openssl_sys::RSA_METHOD,
        priv_enc: unsafe extern "C" fn(
            flen: std::os::raw::c_int,
            from: *const std::os::raw::c_uchar,
            to: *mut std::os::raw::c_uchar,
            rsa: *mut openssl_sys::RSA,
            padding: std::os::raw::c_int,
        ) -> std::os::raw::c_int,
    ) -> std::os::raw::c_int;
    pub fn RSA_meth_set_priv_dec(
        rsa: *mut openssl_sys::RSA_METHOD,
        priv_dec: unsafe extern "C" fn(
            flen: std::os::raw::c_int,
            from: *const std::os::raw::c_uchar,
            to: *mut std::os::raw::c_uchar,
            rsa: *mut openssl_sys::RSA,
            padding: std::os::raw::c_int,
        ) -> std::os::raw::c_int,
    ) -> std::os::raw::c_int;
}
