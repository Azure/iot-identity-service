// Copyright (c) Microsoft. All rights reserved.

//! aziot-tpm-sys
//!
//! Rust FFI to C library interface.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::too_many_lines)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use std::os::raw::{c_int, c_uchar, c_void};

pub type HSM_CLIENT_HANDLE = *mut c_void;

extern "C" {
    pub fn hsm_client_tpm_init() -> c_int;
    pub fn hsm_client_tpm_deinit();

    pub fn hsm_client_tpm_create() -> HSM_CLIENT_HANDLE;
    pub fn hsm_client_tpm_destroy(handle: HSM_CLIENT_HANDLE);
    pub fn hsm_client_tpm_activate_identity_key(
        handle: HSM_CLIENT_HANDLE,
        key: *const c_uchar,
        key_len: usize,
    ) -> c_int;
    pub fn hsm_client_tpm_get_endorsement_key(
        handle: HSM_CLIENT_HANDLE,
        key: *mut *mut c_uchar,
        key_len: *mut usize,
    ) -> c_int;
    pub fn hsm_client_tpm_get_storage_key(
        handle: HSM_CLIENT_HANDLE,
        key: *mut *mut c_uchar,
        key_len: *mut usize,
    ) -> c_int;
    pub fn hsm_client_tpm_sign_data(
        handle: HSM_CLIENT_HANDLE,
        data: *const c_uchar,
        data_len: usize,
        key: *mut *mut c_uchar,
        key_len: *mut usize,
    ) -> c_int;
    pub fn hsm_client_tpm_free_buffer(buffer: *mut c_void);
}
