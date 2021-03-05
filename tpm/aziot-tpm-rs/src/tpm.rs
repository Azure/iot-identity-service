// Copyright (c) Microsoft. All rights reserved.

use std::convert::AsRef;
use std::ops::{Deref, Drop};
use std::os::raw::{c_uchar, c_void};
use std::ptr;
use std::slice;
use std::sync::{Mutex, Once};

use lazy_static::lazy_static;

use aziot_tpm_sys::{
    aziot_tpm_create, aziot_tpm_destroy, aziot_tpm_free_buffer, aziot_tpm_get_keys,
    aziot_tpm_import_auth_key, aziot_tpm_init, aziot_tpm_sign_with_auth_key, AZIOT_TPM_HANDLE,
    LOG_LVL_DEBUG, LOG_LVL_ERROR, LOG_LVL_INFO,
};

use crate::Error;

/// An interface to the TPM interface of an HSM.
#[derive(Debug)]
pub struct Tpm {
    handle: AZIOT_TPM_HANDLE,
}

// SAFETY: Handles don't have thread-affinity
unsafe impl Send for Tpm {}

macro_rules! tpm_buffer_newtype {
    (
        $(#[$attr:meta])*
        pub struct $newtype:ident(TpmBuffer)
    ) => {
        $(#[$attr])*
        pub struct $newtype(TpmBuffer);

        impl Deref for $newtype {
            type Target = [u8];
            fn deref(&self) -> &Self::Target {
                self.0.deref()
            }
        }

        impl AsRef<[u8]> for $newtype {
            fn as_ref(&self) -> &[u8] {
                self.0.as_ref()
            }
        }
    };
}

tpm_buffer_newtype!(
    /// A key generated by the TPM.
    /// Dereferences to a `[u8]`, and implements `AsRef<[u8]>`.
    pub struct TpmKey(TpmBuffer)
);

tpm_buffer_newtype!(
    /// A digest generated by the TPM.
    /// Dereferences to a `[u8]`, and implements `AsRef<[u8]>`.
    pub struct TpmDigest(TpmBuffer)
);

/// The TPM's Endorsement and Storage Root Keys.
pub struct TpmKeys {
    /// The TPM's Endorsement Key
    pub endorsement_key: TpmKey,
    /// The TPM's Storage Root Key
    pub storage_root_key: TpmKey,
}

impl Drop for Tpm {
    fn drop(&mut self) {
        unsafe {
            aziot_tpm_destroy(self.handle);
        }
    }
}

static mut INIT_RESULT: Option<Result<(), Error>> = None;
static INIT_C_LIB: Once = Once::new();

lazy_static! {
    static ref TPM_CREATE_GUARD: Mutex<()> = Mutex::new(());
}

impl Tpm {
    /// Create a new TPM implementation for the HSM API.
    pub fn new() -> Result<Tpm, Error> {
        // ensure that `aziot_tpm_init` is only called once
        INIT_C_LIB.call_once(|| unsafe {
            INIT_RESULT = {
                let log_level = match log::max_level() {
                    l if l <= log::Level::Error => LOG_LVL_ERROR,
                    l if l <= log::Level::Info => LOG_LVL_INFO,
                    l if l <= log::Level::Debug => LOG_LVL_DEBUG,
                    _ => LOG_LVL_INFO,
                };

                let result = aziot_tpm_init(log_level) as isize;
                if result == 0 {
                    Some(Ok(()))
                } else {
                    Some(Err(Error::Init(result)))
                }
            }
        });
        unsafe { INIT_RESULT.unwrap()? };

        // ensure that calls to `aziot_tpm_create` are serialized
        let handle = {
            let _guard = TPM_CREATE_GUARD.lock().expect("failed to lock TPM mutex");
            unsafe { aziot_tpm_create() }
        };

        if handle.is_null() {
            return Err(Error::NullResponse);
        }
        Ok(Tpm { handle })
    }

    /// Imports key that has been previously encrypted with the endorsement key
    /// and storage root key into the TPM key storage.
    pub fn import_auth_key(&self, key: &[u8]) -> Result<(), Error> {
        let result = unsafe { aziot_tpm_import_auth_key(self.handle, key.as_ptr(), key.len()) };
        match result {
            0 => Ok(()),
            r => Err(r.into()),
        }
    }

    /// Retrieves the endorsement and storage root keys of the TPM.
    pub fn get_tpm_keys(&self) -> Result<TpmKeys, Error> {
        let mut ek = ptr::null_mut();
        let mut ek_ln: usize = 0;
        let mut srk = ptr::null_mut();
        let mut srk_ln: usize = 0;

        let result =
            unsafe { aziot_tpm_get_keys(self.handle, &mut ek, &mut ek_ln, &mut srk, &mut srk_ln) };
        match result {
            0 => Ok(TpmKeys {
                endorsement_key: TpmKey(TpmBuffer::new(ek as *const _, ek_ln)),
                storage_root_key: TpmKey(TpmBuffer::new(srk as *const _, srk_ln)),
            }),
            r => Err(r.into()),
        }
    }

    /// Hashes the parameter data with the key previously stored in the TPM and
    /// returns the value.
    pub fn sign_with_auth_key(&self, data: &[u8]) -> Result<TpmDigest, Error> {
        let mut key_ln: usize = 0;
        let mut ptr = ptr::null_mut();

        let result = unsafe {
            aziot_tpm_sign_with_auth_key(
                self.handle,
                data.as_ptr(),
                data.len(),
                &mut ptr,
                &mut key_ln,
            )
        };
        match result {
            0 => Ok(TpmDigest(TpmBuffer::new(ptr as *const _, key_ln))),
            r => Err(r.into()),
        }
    }
}

/// When buffer data is returned from TPM interface, it is placed in this struct.
/// This is a buffer allocated by the C library.
#[derive(Debug)]
pub struct TpmBuffer {
    key: *const c_uchar,
    len: usize,
}

impl Drop for TpmBuffer {
    fn drop(&mut self) {
        unsafe { aziot_tpm_free_buffer(self.key as *mut c_void) };
    }
}

impl TpmBuffer {
    pub fn new(key: *const c_uchar, len: usize) -> TpmBuffer {
        TpmBuffer { key, len }
    }
}

impl Deref for TpmBuffer {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl AsRef<[u8]> for TpmBuffer {
    fn as_ref(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.key, self.len) }
    }
}
