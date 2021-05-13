// Copyright (c) Microsoft. All rights reserved.

//! Function list types.

pub mod v2_0_0_0;

pub mod v2_1_0_0;

/// The base struct of all of function lists.
#[derive(Debug)]
#[repr(C)]
pub struct AZIOT_KEYS_FUNCTION_LIST {
    /// The version of the API represented in this function list.
    ///
    /// The specific subtype of `AZIOT_KEYS_FUNCTION_LIST` can be determined by inspecting this value.
    pub version: crate::AZIOT_KEYS_VERSION,
}
