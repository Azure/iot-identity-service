// Copyright (c) Microsoft. All rights reserved.

//! Idiomatic Rust bindings to the `aziot-tpm` C library.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::module_name_repetitions)]
#![deny(missing_docs)]

mod error;
mod tpm;

pub use crate::error::Error;
pub use crate::tpm::{Tpm, TpmDigest, TpmKey, TpmKeys};

// Traits

/// A Trait for importing and retrieving keys from a TPM.
pub trait ManageTpmKeys {
    /// Imports key that has been previously encrypted with the endorsement key
    /// and storage root key into the TPM key storage.
    fn import_auth_key(&self, key: &[u8]) -> Result<(), Error>;
    /// Retrieves the endorsement and storage root keys of the TPM.
    fn get_tpm_keys(&self) -> Result<TpmKeys, Error>;
}

/// A Trait for singing data using keys stored within a TPM.
pub trait SignWithTpm {
    /// Hashes the parameter data with the key previously stored in the TPM and
    /// returns the value.
    fn sign_with_auth_key(&self, data: &[u8]) -> Result<TpmDigest, Error>;
}
