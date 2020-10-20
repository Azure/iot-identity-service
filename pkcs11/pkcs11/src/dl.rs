// Copyright (c) Microsoft. All rights reserved.

/// Represents a dynamically loaded library.
pub(crate) struct Library {
    handle: *mut std::ffi::c_void,
}

impl Library {
    /// Load the library at the specified path.
    pub(crate) unsafe fn load(path: &std::path::Path) -> Result<Self, String> {
        let path = std::os::unix::ffi::OsStrExt::as_bytes(path.as_os_str()).to_owned();
        let path = std::ffi::CString::new(path).map_err(|err| err.to_string())?;

        let handle = libc::dlopen(path.as_ptr(), libc::RTLD_LAZY | libc::RTLD_LOCAL);
        if handle.is_null() {
            return Err(dlerror());
        }

        Ok(Library { handle })
    }

    /// Obtain a symbol from this library of the specified type.
    pub(crate) unsafe fn symbol<'library, F>(
        &'library self,
        name: &std::ffi::CStr,
    ) -> Result<Symbol<'library, F>, String> {
        let inner = libc::dlsym(self.handle, name.as_ptr());
        if inner.is_null() {
            return Err(dlerror());
        }

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
            let _ = libc::dlclose(self.handle);
        }
    }
}

/// A symbol obtained from a [`Library`].
pub(crate) struct Symbol<'library, F> {
    inner: *mut std::ffi::c_void,
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
            &*(&self.inner as *const _ as *const F)
        }
    }
}

unsafe fn dlerror() -> String {
    let error = libc::dlerror();
    let error = std::ffi::CStr::from_ptr(error);
    let error = error.to_string_lossy();
    error.into_owned()
}
