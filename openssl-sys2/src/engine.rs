// Copyright (c) Microsoft. All rights reserved.

//! `engine.h`

// Using engines

#[repr(C)]
pub struct UI_METHOD([u8; 0]);

extern "C" {
    pub fn ENGINE_new() -> *mut openssl_sys::ENGINE;
    pub fn ENGINE_by_id(id: *const std::os::raw::c_char) -> *mut openssl_sys::ENGINE;
    pub fn ENGINE_finish(e: *mut openssl_sys::ENGINE) -> std::os::raw::c_int;
    pub fn ENGINE_free(e: *mut openssl_sys::ENGINE) -> std::os::raw::c_int;
    pub fn ENGINE_get_name(e: *const openssl_sys::ENGINE) -> *const std::os::raw::c_char;
    pub fn ENGINE_init(e: *mut openssl_sys::ENGINE) -> std::os::raw::c_int;
    pub fn ENGINE_load_private_key(
        e: *mut openssl_sys::ENGINE,
        key_id: *const std::os::raw::c_char,
        ui_method: *mut UI_METHOD,
        callback_data: *mut std::ffi::c_void,
    ) -> *mut openssl_sys::EVP_PKEY;
    pub fn ENGINE_load_public_key(
        e: *mut openssl_sys::ENGINE,
        key_id: *const std::os::raw::c_char,
        ui_method: *mut UI_METHOD,
        callback_data: *mut std::ffi::c_void,
    ) -> *mut openssl_sys::EVP_PKEY;
}

// Implementing engines

pub type ENGINE_GEN_INT_FUNC_PTR =
    unsafe extern "C" fn(e: *mut openssl_sys::ENGINE) -> std::os::raw::c_int;

pub type ENGINE_LOAD_KEY_PTR = unsafe extern "C" fn(
    e: *mut openssl_sys::ENGINE,
    key_id: *const std::os::raw::c_char,
    ui_method: *mut UI_METHOD,
    callback_data: *mut std::ffi::c_void,
) -> *mut openssl_sys::EVP_PKEY;

pub type ENGINE_PKEY_METHS_PTR = unsafe extern "C" fn(
    e: *mut openssl_sys::ENGINE,
    pmeth: *mut *const crate::EVP_PKEY_METHOD,
    nids: *mut *const std::os::raw::c_int,
    nid: std::os::raw::c_int,
) -> std::os::raw::c_int;

pub const ENGINE_FLAGS_BY_ID_COPY: std::os::raw::c_int = 0x0004;

extern "C" {
    pub fn ENGINE_add(e: *mut openssl_sys::ENGINE) -> std::os::raw::c_int;
    pub fn ENGINE_set_flags(
        e: *mut openssl_sys::ENGINE,
        flags: std::os::raw::c_int,
    ) -> std::os::raw::c_int;
    pub fn ENGINE_set_id(
        e: *mut openssl_sys::ENGINE,
        id: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;
    pub fn ENGINE_set_name(
        e: *mut openssl_sys::ENGINE,
        name: *const std::os::raw::c_char,
    ) -> std::os::raw::c_int;
    pub fn ENGINE_set_init_function(
        e: *mut openssl_sys::ENGINE,
        ctrl_f: ENGINE_GEN_INT_FUNC_PTR,
    ) -> std::os::raw::c_int;

    pub fn ENGINE_set_load_privkey_function(
        e: *mut openssl_sys::ENGINE,
        loadpriv_f: ENGINE_LOAD_KEY_PTR,
    ) -> std::os::raw::c_int;
    pub fn ENGINE_set_load_pubkey_function(
        e: *mut openssl_sys::ENGINE,
        loadpub_f: ENGINE_LOAD_KEY_PTR,
    ) -> std::os::raw::c_int;
    pub fn ENGINE_set_pkey_meths(
        e: *mut openssl_sys::ENGINE,
        f: ENGINE_PKEY_METHS_PTR,
    ) -> std::os::raw::c_int;

    pub fn ENGINE_get_ex_data(
        e: *const openssl_sys::ENGINE,
        idx: std::os::raw::c_int,
    ) -> *mut std::ffi::c_void;
    pub fn ENGINE_set_ex_data(
        e: *mut openssl_sys::ENGINE,
        idx: std::os::raw::c_int,
        arg: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int;
}
