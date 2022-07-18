// Copyright (c) Microsoft. All rights reserved.

pub use esys_sys::ESYS_TR;

use std::fmt;

use crate::{private, EsysContext};

pub const PERSISTENT_OBJECT_BASE: u32 = 0x81_00_00_00;
pub const ENDORSEMENT_KEY: u32 = PERSISTENT_OBJECT_BASE + 0x01_00_01;
pub const STORAGE_ROOT_KEY: u32 = PERSISTENT_OBJECT_BASE + 0x00_10_00;

/// Returns the index of the resource within the ESYS context. Note that this
/// is not equivalent to the index of the resource on the TPM.
pub trait EsysResource: private::Sealed {
    fn tr(&self) -> ESYS_TR;
}

/// Trusted Platform Module Library Part 1: Architecture: 15.7 Persistent Object Handles
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Persistent(ESYS_TR);

impl Persistent {
    pub const NONE: Self = Self(esys_sys::ESYS_TR_NONE);

    pub const PASSWORD_SESSION: Self = Self(esys_sys::ESYS_TR_PASSWORD);

    pub const OWNER_HIERARCHY: Self = Self(esys_sys::ESYS_TR_RH_OWNER);
    pub const NULL_HIERARCHY: Self = Self(esys_sys::ESYS_TR_RH_NULL);
    pub const ENDORSEMENT_HIERARCHY: Self = Self(esys_sys::ESYS_TR_RH_ENDORSEMENT);
    pub const PLATFORM_HIERARCHY: Self = Self(esys_sys::ESYS_TR_RH_PLATFORM);

    #[must_use]
    pub fn new(index: ESYS_TR) -> Self {
        Self(index)
    }
}

impl private::Sealed for Persistent {}

impl EsysResource for Persistent {
    fn tr(&self) -> ESYS_TR {
        self.0
    }
}

/// Trusted Platform Module Library Part 1: Architecture: 15.6 Transient Object Handles
pub struct Transient<'a> {
    index: ESYS_TR,
    context: &'a EsysContext,
}

impl<'a> Transient<'a> {
    #[must_use]
    pub fn new(index: ESYS_TR, context: &'a EsysContext) -> Self {
        Self { index, context }
    }
}

impl PartialEq for Transient<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && std::ptr::eq(self.context, other.context)
    }
}

impl Eq for Transient<'_> {}

impl private::Sealed for Transient<'_> {}

impl EsysResource for Transient<'_> {
    fn tr(&self) -> ESYS_TR {
        self.index
    }
}

impl fmt::Debug for Transient<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Transient").field(&self.index).finish()
    }
}

impl Drop for Transient<'_> {
    fn drop(&mut self) {
        let handle = std::mem::replace(&mut self.index, esys_sys::ESYS_TR_NONE);
        if let Err(e) = self.context.flush(handle) {
            log::error!("could not flush Transient(0x{:08X}): {}", handle, e);
        }
    }
}
