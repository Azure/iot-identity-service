// Copyright (c) Microsoft. All rights reserved.

//! Rust FFI to C library interface.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::too_many_lines)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use std::os::raw::{c_int, c_uchar, c_void};

pub type AZIOT_TPM_HANDLE = *mut c_void;

pub const LOG_LVL_DEBUG: c_int = 0;
pub const LOG_LVL_INFO: c_int = 1;
pub const LOG_LVL_ERROR: c_int = 2;

extern "C" {
    pub fn aziot_tpm_init(log_level: c_int) -> c_int;
    pub fn aziot_tpm_deinit();

    pub fn aziot_tpm_create() -> AZIOT_TPM_HANDLE;
    pub fn aziot_tpm_destroy(handle: AZIOT_TPM_HANDLE);
    pub fn aziot_tpm_import_auth_key(
        handle: AZIOT_TPM_HANDLE,
        key: *const c_uchar,
        key_len: usize,
    ) -> c_int;
    pub fn aziot_tpm_get_keys(
        handle: AZIOT_TPM_HANDLE,
        ek: *mut *mut c_uchar,
        ek_len: *mut usize,
        srk: *mut *mut c_uchar,
        srk_len: *mut usize,
    ) -> c_int;
    pub fn aziot_tpm_sign_with_auth_key(
        handle: AZIOT_TPM_HANDLE,
        data: *const c_uchar,
        data_len: usize,
        key: *mut *mut c_uchar,
        key_len: *mut usize,
    ) -> c_int;
    pub fn aziot_tpm_free_buffer(buffer: *mut c_void);
}
