// Copyright (c) Microsoft. All rights reserved.

use std::ptr::NonNull;

/// Represents a dynamically loaded library.
pub(crate) struct Library {
    handle: NonNull<std::ffi::c_void>,
}

impl Library {
    /// Load the library at the specified path.
    pub(crate) unsafe fn load(path: &std::path::Path) -> Result<Self, String> {
        let path = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()).to_owned();
        let path = std::ffi::CString::new(path).map_err(|err| err.to_string())?;

        let handle = NonNull::new(libc::dlopen(
            path.as_ptr(),
            libc::RTLD_LAZY | libc::RTLD_LOCAL,
        ))
        .ok_or_else(|| dlerror())?;

        Ok(Library { handle })
    }

    /// Obtain a symbol from this library of the specified type.
    pub(crate) unsafe fn symbol<'library, F>(
        &'library mut self,
        name: &std::ffi::CStr,
    ) -> Result<Symbol<'library, F>, String> {
        let inner = NonNull::new(libc::dlsym(self.handle.as_mut(), name.as_ptr()))
            .ok_or_else(|| dlerror())?;

        Ok(Symbol {
            inner,
            _library: Default::default(),
            _type: Default::default(),
        })
    }
}

impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            let _ = libc::dlclose(self.handle.as_mut());
        }
    }
}

/// A symbol obtained from a [`Library`].
pub(crate) struct Symbol<'library, F> {
    inner: NonNull<std::ffi::c_void>,
    _library: std::marker::PhantomData<&'library Library>,
    _type: std::marker::PhantomData<F>,
}

impl<F> std::ops::Deref for Symbol<'_, F> {
    type Target = F;

    fn deref(&self) -> &Self::Target {
        unsafe {
            // F is expected to be a fn(...) and fn are themselves pointers. So self.inner is that fn.
            // The signature of `Deref::deref` requires this code to return a &fn, not the fn itself.
            // So we want to return the address of self.inner, and not self.inner itself.
            &*std::ptr::addr_of!(self.inner).cast::<F>()
        }
    }
}

unsafe fn dlerror() -> String {
    let error = libc::dlerror();
    let error = std::ffi::CStr::from_ptr(error);
    let error = error.to_string_lossy();
    error.into_owned()
}
