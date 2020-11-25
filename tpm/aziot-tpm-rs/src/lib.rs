// Copyright (c) Microsoft. All rights reserved.

//! Idiomatic Rust bindings to the `aziot-tpm` C library.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]
#![deny(missing_docs)]

mod error;
mod tpm;

pub use crate::error::Error;
pub use crate::tpm::{Tpm, TpmDigest, TpmKey, TpmKeys};
