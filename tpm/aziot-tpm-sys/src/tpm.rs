// Copyright (c) Microsoft. All rights reserved.

use std::os::raw::{c_int, c_uchar};

use crate::{HSM_CLIENT_CREATE, HSM_CLIENT_DESTROY, HSM_CLIENT_FREE_BUFFER, HSM_CLIENT_HANDLE};

// TPM

pub type HSM_CLIENT_ACTIVATE_IDENTITY_KEY = Option<
    unsafe extern "C" fn(handle: HSM_CLIENT_HANDLE, key: *const c_uchar, key_len: usize) -> c_int,
>;
pub type HSM_CLIENT_GET_ENDORSEMENT_KEY = Option<
    unsafe extern "C" fn(
        handle: HSM_CLIENT_HANDLE,
        key: *mut *mut c_uchar,
        key_len: *mut usize,
    ) -> c_int,
>;
pub type HSM_CLIENT_GET_STORAGE_ROOT_KEY = Option<
    unsafe extern "C" fn(
        handle: HSM_CLIENT_HANDLE,
        key: *mut *mut c_uchar,
        key_len: *mut usize,
    ) -> c_int,
>;
pub type HSM_CLIENT_SIGN_WITH_IDENTITY = Option<
    unsafe extern "C" fn(
        handle: HSM_CLIENT_HANDLE,
        data: *const c_uchar,
        data_len: usize,
        key: *mut *mut c_uchar,
        key_len: *mut usize,
    ) -> c_int,
>;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct HSM_CLIENT_TPM_INTERFACE {
    pub hsm_client_tpm_create: HSM_CLIENT_CREATE,
    pub hsm_client_tpm_destroy: HSM_CLIENT_DESTROY,
    pub hsm_client_activate_identity_key: HSM_CLIENT_ACTIVATE_IDENTITY_KEY,
    pub hsm_client_get_ek: HSM_CLIENT_GET_ENDORSEMENT_KEY,
    pub hsm_client_get_srk: HSM_CLIENT_GET_STORAGE_ROOT_KEY,
    pub hsm_client_sign_with_identity: HSM_CLIENT_SIGN_WITH_IDENTITY,
    pub hsm_client_free_buffer: HSM_CLIENT_FREE_BUFFER,
}

impl Default for HSM_CLIENT_TPM_INTERFACE {
    fn default() -> HSM_CLIENT_TPM_INTERFACE {
        HSM_CLIENT_TPM_INTERFACE {
            hsm_client_tpm_create: None,
            hsm_client_tpm_destroy: None,
            hsm_client_activate_identity_key: None,
            hsm_client_get_ek: None,
            hsm_client_get_srk: None,
            hsm_client_sign_with_identity: None,
            hsm_client_free_buffer: None,
        }
    }
}

#[test]
fn bindgen_test_layout_HSM_CLIENT_TPM_INTERFACE() {
    use crate::tpm::HSM_CLIENT_TPM_INTERFACE;

    assert_eq!(
        ::std::mem::size_of::<HSM_CLIENT_TPM_INTERFACE>(),
        7_usize * ::std::mem::size_of::<usize>(),
        concat!("Size of: ", stringify!(HSM_CLIENT_TPM_INTERFACE))
    );
    assert_eq!(
        ::std::mem::align_of::<HSM_CLIENT_TPM_INTERFACE>(),
        ::std::mem::size_of::<usize>(),
        concat!("Alignment of ", stringify!(HSM_CLIENT_TPM_INTERFACE))
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<HSM_CLIENT_TPM_INTERFACE>())).hsm_client_tpm_create as *const _
                as usize
        },
        0_usize,
        concat!(
            "Offset of field: ",
            stringify!(HSM_CLIENT_TPM_INTERFACE),
            "::",
            stringify!(hsm_client_tpm_create)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<HSM_CLIENT_TPM_INTERFACE>())).hsm_client_tpm_destroy as *const _
                as usize
        },
        ::std::mem::size_of::<usize>(),
        concat!(
            "Offset of field: ",
            stringify!(HSM_CLIENT_TPM_INTERFACE),
            "::",
            stringify!(hsm_client_tpm_destroy)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<HSM_CLIENT_TPM_INTERFACE>())).hsm_client_activate_identity_key
                as *const _ as usize
        },
        2_usize * ::std::mem::size_of::<usize>(),
        concat!(
            "Offset of field: ",
            stringify!(HSM_CLIENT_TPM_INTERFACE),
            "::",
            stringify!(hsm_client_activate_identity_key)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<HSM_CLIENT_TPM_INTERFACE>())).hsm_client_get_ek as *const _
                as usize
        },
        3_usize * ::std::mem::size_of::<usize>(),
        concat!(
            "Offset of field: ",
            stringify!(HSM_CLIENT_TPM_INTERFACE),
            "::",
            stringify!(hsm_client_get_ek)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<HSM_CLIENT_TPM_INTERFACE>())).hsm_client_get_srk as *const _
                as usize
        },
        4_usize * ::std::mem::size_of::<usize>(),
        concat!(
            "Offset of field: ",
            stringify!(HSM_CLIENT_TPM_INTERFACE),
            "::",
            stringify!(hsm_client_get_srk)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<HSM_CLIENT_TPM_INTERFACE>())).hsm_client_sign_with_identity
                as *const _ as usize
        },
        5_usize * ::std::mem::size_of::<usize>(),
        concat!(
            "Offset of field: ",
            stringify!(HSM_CLIENT_TPM_INTERFACE),
            "::",
            stringify!(hsm_client_sign_with_identity)
        )
    );
    assert_eq!(
        unsafe {
            &(*(::std::ptr::null::<HSM_CLIENT_TPM_INTERFACE>())).hsm_client_free_buffer as *const _
                as usize
        },
        6_usize * ::std::mem::size_of::<usize>(),
        concat!(
            "Offset of field: ",
            stringify!(HSM_CLIENT_TPM_INTERFACE),
            "::",
            stringify!(hsm_client_free_buffer)
        )
    );
}
