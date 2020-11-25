// Copyright (c) Microsoft. All rights reserved.

use std::fmt;
use std::fmt::Display;
use std::os::raw::c_int;

/// Errors which may occur while accessing a TPM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// TPM Init failure.
    Init(isize),
    /// TPM API failure.
    Api(c_int),
    /// TPM API returned an invalid null response.
    NullResponse,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Init(e) => write!(f, "TPM Init failure: {}", e),
            Error::Api(e) => write!(f, "TPM API failure occurred: {}", e),
            Error::NullResponse => write!(f, "TPM API returned an invalid null response"),
        }
    }
}

impl std::error::Error for Error {}

impl From<c_int> for Error {
    fn from(result: c_int) -> Self {
        Error::Api(result)
    }
}
