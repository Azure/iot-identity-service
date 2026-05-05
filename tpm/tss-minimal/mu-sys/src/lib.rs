// Copyright (c) Microsoft. All rights reserved.

#![expect(nonstandard_style)]

use types_sys::{TPM2B_ENCRYPTED_SECRET, TPM2B_ID_OBJECT, TPM2B_PRIVATE, TPM2B_PUBLIC};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
