// Copyright (c) Microsoft. All rights reserved.

#[derive(Clone, Copy)]
pub(crate) struct ExIndices {
    pub(crate) engine: openssl::ex_data::Index<openssl_sys::ENGINE, crate::engine::Engine>,
    pub(crate) ec_key: openssl::ex_data::Index<
        openssl_sys::EC_KEY,
        pkcs11::Object<openssl::ec::EcKey<openssl::pkey::Private>>,
    >,
    pub(crate) rsa: openssl::ex_data::Index<
        openssl_sys::RSA,
        pkcs11::Object<openssl::rsa::Rsa<openssl::pkey::Private>>,
    >,
}

pub(crate) unsafe fn ex_indices() -> ExIndices {
    static mut RESULT: *const ExIndices = std::ptr::null();
    static RESULT_INIT: std::sync::Once = std::sync::Once::new();

    RESULT_INIT.call_once(|| {
        // If we can't get the ex indices, log the error and swallow it, leaving RESULT as nullptr.
        // After the Once initializer, the code will assert and abort.
        let _ = super::r#catch(None, || {
            extern "C" {
                fn pkcs11_get_engine_ex_index() -> std::os::raw::c_int;
                fn pkcs11_get_ec_key_ex_index() -> std::os::raw::c_int;
                fn pkcs11_get_rsa_ex_index() -> std::os::raw::c_int;
            }

            let engine_ex_index = pkcs11_get_engine_ex_index();
            if engine_ex_index == -1 {
                return Err(format!(
                    "could not register ENGINE ex index: {}",
                    openssl::error::ErrorStack::get()
                )
                .into());
            }

            let ec_key_ex_index = pkcs11_get_ec_key_ex_index();
            if ec_key_ex_index == -1 {
                return Err(format!(
                    "could not register EC_KEY ex index: {}",
                    openssl::error::ErrorStack::get()
                )
                .into());
            }

            let rsa_ex_index = pkcs11_get_rsa_ex_index();
            if rsa_ex_index == -1 {
                return Err(format!(
                    "could not register RSA ex index: {}",
                    openssl::error::ErrorStack::get()
                )
                .into());
            }

            let ex_indices = ExIndices {
                engine: openssl::ex_data::Index::from_raw(engine_ex_index),
                ec_key: openssl::ex_data::Index::from_raw(ec_key_ex_index),
                rsa: openssl::ex_data::Index::from_raw(rsa_ex_index),
            };
            RESULT = Box::into_raw(Box::new(ex_indices));

            Ok(())
        });
    });

    assert!(!RESULT.is_null(), "ex indices could not be initialized");
    *RESULT
}

pub(crate) trait HasExData<T>: openssl2::ExDataAccessors + Sized {
    unsafe fn index() -> openssl::ex_data::Index<Self, T>;
}

pub(crate) unsafe fn get<T, U>(this: &T) -> Result<&U, openssl2::Error>
where
    T: HasExData<U>,
{
    let ex_index = <T as HasExData<U>>::index().as_raw();

    let ex_data: *const U = openssl2::openssl_returns_nonnull(
        (<T as openssl2::ExDataAccessors>::GET_FN)(this, ex_index),
    )? as _;

    Ok(&*ex_data)
}

pub(crate) unsafe fn set<T, U>(this: *mut T, ex_data: U) -> Result<(), openssl2::Error>
where
    T: HasExData<U>,
{
    let ex_index = <T as HasExData<U>>::index().as_raw();

    let ex_data = std::sync::Arc::new(ex_data);
    let ex_data = std::sync::Arc::into_raw(ex_data) as _;

    openssl2::openssl_returns_1((<T as openssl2::ExDataAccessors>::SET_FN)(
        this, ex_index, ex_data,
    ))?;

    Ok(())
}

pub(crate) unsafe fn dup<T, U>(from_d: *mut std::ffi::c_void, idx: std::os::raw::c_int)
where
    T: HasExData<U>,
{
    let ex_index = <T as HasExData<U>>::index().as_raw();
    assert_eq!(idx, ex_index);

    // Although `dup_func`'s signature types `from_d` as `void*`, it is in fact a `void**` - it points to the pointer returned by
    // calling `CRYPTO_get_ex_data` on the `from` object. After `dup_func` returns, openssl takes whatever `from_d` is pointing to,
    // and sets it as the ex data of the `to` object using `CRYPTO_set_ex_data`.
    //
    // Ref: https://www.openssl.org/docs/man1.1.1/man3/CRYPTO_get_ex_new_index.html (search for `dup_func`)
    // Ref: https://github.com/openssl/openssl/blob/bd65afdb21942676e7e4ce77adaaec697624b65f/crypto/ex_data.c#L321-L326
    //
    // In our case, the ex data is `*const U`, thus `from_d` is `*mut *const U`
    //
    // We don't need to change the value inside `from_d`. We just need to bump the `Arc` refcount.

    let ptr: *mut *const U = from_d as _;
    if !ptr.is_null() {
        let ex_data = std::sync::Arc::from_raw(*ptr);

        // Bump the refcount ...
        let ex_data_clone = ex_data.clone();

        // ... and `forget` the two `Arc`s, so that they don't get dropped and decrease the refcount again.
        std::mem::forget(ex_data);
        std::mem::forget(ex_data_clone);
    }
}

pub(crate) unsafe fn free<T, U>(ptr: *mut std::ffi::c_void, idx: std::os::raw::c_int)
where
    T: HasExData<U>,
{
    let ex_index = <T as HasExData<U>>::index().as_raw();
    assert_eq!(idx, ex_index);

    let ptr: *mut U = ptr as _;
    if !ptr.is_null() {
        let ex_data = std::sync::Arc::from_raw(ptr);
        drop(ex_data);
    }
}
