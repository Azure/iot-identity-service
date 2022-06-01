// Copyright (c) Microsoft. All rights reserved.

use std::ffi::CStr;
use std::fmt;

pub fn try_decode_rc(rc: u32) -> Option<String> {
    let msg = unsafe { rc_sys::Tss2_RC_Decode(rc) };

    if msg.is_null() {
        return None;
    }

    let cstr = unsafe { CStr::from_ptr(msg) };
    cstr.to_str().ok().map(ToOwned::to_owned)
}

#[macro_export]
macro_rules! wrap_rc {
    ($e:expr) => {{
        let rc = unsafe { $e };
        if rc > 0 {
            Err(crate::Error(rc))
        } else {
            Ok(())
        }
    }};
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub struct Error(pub(crate) u32);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            crate::try_decode_rc(self.0).as_deref().unwrap_or("unknown")
        )
    }
}

impl std::error::Error for Error {}
