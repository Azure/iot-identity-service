use std::ffi::CStr;
use std::fmt;
use std::sync::Mutex;

pub fn try_decode_rc(rc: u32) -> Option<String> {
    // Tss2_RC_Decode uses thread-local storage, and overwrites the
    // return address on each invocation.  So, we have to make sure to
    // save the error message contents before the next invocation on
    // this thread.
    thread_local! {
        static MUTEX: Mutex<()> = Mutex::new(());
    }

    MUTEX.with(|m| {
        // There are technically no invariants to protect, so another
        // option is to replace `.expect(...)` with
        // `.unwrap_or_else(std::sync::PoisonError::into_inner)`.
        let _lock = m.lock().expect("poisoned mutex");
        let msg = unsafe { rc_sys::Tss2_RC_Decode(rc) };

        if msg.is_null() {
            return None;
        }

        let cstr = unsafe { CStr::from_ptr(msg) };
        cstr.to_str().ok().map(ToOwned::to_owned)
    })
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
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            crate::try_decode_rc(self.0).as_deref().unwrap_or("unknown")
        )
    }
}

impl std::error::Error for Error {}
