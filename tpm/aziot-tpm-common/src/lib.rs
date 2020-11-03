// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

pub struct TpmKeys {
    pub endorsement_key: Vec<u8>,
    pub storage_root_key: Vec<u8>,
}
