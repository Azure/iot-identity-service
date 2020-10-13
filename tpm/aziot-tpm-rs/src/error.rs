// Copyright (c) Microsoft. All rights reserved.

use std::fmt;
use std::fmt::Display;
use std::os::raw::c_int;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Init(isize),
    Api(c_int),
    NoneFn,
    NullResponse,
}

impl Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Init(e) => write!(f, "HSM Init failure: {}", e),
            Error::Api(e) => write!(f, "HSM API failure occurred: {}", e),
            Error::NoneFn => write!(f, "HSM API Not Implemented"),
            Error::NullResponse => write!(f, "HSM API returned an invalid null response"),
        }
    }
}

impl From<c_int> for Error {
    fn from(result: c_int) -> Self {
        Error::Api(result)
    }
}

impl From<isize> for Error {
    fn from(result: isize) -> Self {
        Error::Init(result)
    }
}
