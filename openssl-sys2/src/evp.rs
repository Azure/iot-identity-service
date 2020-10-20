// Copyright (c) Microsoft. All rights reserved.

//! `evp.h`

#[repr(C)]
pub struct EVP_PKEY_METHOD([u8; 0]);

pub const EVP_PKEY_FLAG_AUTOARGLEN: std::os::raw::c_int = 0x0002;

extern "C" {
    pub fn EVP_PKEY_CTX_get0_pkey(
        ctx: *mut openssl_sys::EVP_PKEY_CTX,
    ) -> *mut openssl_sys::EVP_PKEY;
}

extern "C" {
    pub fn EVP_PKEY_meth_copy(dst: *mut EVP_PKEY_METHOD, src: *const EVP_PKEY_METHOD);
    pub fn EVP_PKEY_meth_find(r#type: std::os::raw::c_int) -> *const EVP_PKEY_METHOD;
    pub fn EVP_PKEY_meth_new(
        id: std::os::raw::c_int,
        flags: std::os::raw::c_int,
    ) -> *mut EVP_PKEY_METHOD;

    #[cfg(ossl110)]
    pub fn EVP_PKEY_meth_get_sign(
        pmeth: *const EVP_PKEY_METHOD,
        psign_init: *mut Option<
            unsafe extern "C" fn(ctx: *mut openssl_sys::EVP_PKEY_CTX) -> std::os::raw::c_int,
        >,
        psign: *mut Option<
            unsafe extern "C" fn(
                ctx: *mut openssl_sys::EVP_PKEY_CTX,
                sig: *mut std::os::raw::c_uchar,
                siglen: *mut usize,
                tbs: *const std::os::raw::c_uchar,
                tbslen: usize,
            ) -> std::os::raw::c_int,
        >,
    );
    #[cfg(ossl110)]
    pub fn EVP_PKEY_meth_set_sign(
        pmeth: *mut EVP_PKEY_METHOD,
        sign_init: Option<
            unsafe extern "C" fn(ctx: *mut openssl_sys::EVP_PKEY_CTX) -> std::os::raw::c_int,
        >,
        sign: Option<
            unsafe extern "C" fn(
                ctx: *mut openssl_sys::EVP_PKEY_CTX,
                sig: *mut std::os::raw::c_uchar,
                siglen: *mut usize,
                tbs: *const std::os::raw::c_uchar,
                tbslen: usize,
            ) -> std::os::raw::c_int,
        >,
    );
}

extern "C" {
    #[cfg(ossl110)]
    pub fn EVP_PKEY_set1_engine(
        pkey: *mut openssl_sys::EVP_PKEY,
        e: *mut openssl_sys::ENGINE,
    ) -> std::os::raw::c_int;
}
