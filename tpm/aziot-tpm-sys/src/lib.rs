// Copyright (c) Microsoft. All rights reserved.

//! iot-hsm-sys
//! Rust FFI to C library interface
//! Based off of <https://github.com/Azure/azure-iot-hsm-c/inc/hsm_client_data.h>
//! Commit id: 11dd77758c6ed1cb06b7c0ba40fdd49bd0d7d3f1
//!
//! Intitial version created through bindgen <https://docs.rs/bindgen/>

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::doc_markdown, // bindgen-generated docs
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::use_self // bindgen-generated signatures
)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use std::os::raw::{c_int, c_uchar, c_void};

mod tpm;

pub use tpm::HSM_CLIENT_TPM_INTERFACE;

pub type HSM_CLIENT_HANDLE = *mut c_void;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SIZED_BUFFER {
    pub buffer: *mut c_uchar,
    pub size: usize,
}

#[test]
fn bindgen_test_layout_SIZED_BUFFER() {
    assert_eq!(
        ::std::mem::size_of::<SIZED_BUFFER>(),
        2_usize * ::std::mem::size_of::<usize>(),
        concat!("Size of: ", stringify!(SIZED_BUFFER))
    );
    assert_eq!(
        ::std::mem::align_of::<SIZED_BUFFER>(),
        ::std::mem::size_of::<usize>(),
        concat!("Alignment of ", stringify!(SIZED_BUFFER))
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<SIZED_BUFFER>())).buffer as *const _ as usize },
        0_usize,
        concat!(
            "Offset of field: ",
            stringify!(SIZED_BUFFER),
            "::",
            stringify!(buffer)
        )
    );
    assert_eq!(
        unsafe { &(*(::std::ptr::null::<SIZED_BUFFER>())).size as *const _ as usize },
        ::std::mem::size_of::<usize>(),
        concat!(
            "Offset of field: ",
            stringify!(SIZED_BUFFER),
            "::",
            stringify!(size)
        )
    );
}

pub type HSM_CLIENT_CREATE = Option<unsafe extern "C" fn() -> HSM_CLIENT_HANDLE>;
pub type HSM_CLIENT_DESTROY = Option<unsafe extern "C" fn(handle: HSM_CLIENT_HANDLE)>;
pub type HSM_CLIENT_FREE_BUFFER = Option<unsafe extern "C" fn(buffer: *mut c_void)>;

extern "C" {
    pub fn hsm_client_tpm_interface() -> *const HSM_CLIENT_TPM_INTERFACE;
}

extern "C" {
    pub fn hsm_client_tpm_init() -> c_int;
}
extern "C" {
    pub fn hsm_client_tpm_deinit();
}
