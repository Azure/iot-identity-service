// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::doc_markdown, // clippy wants "IoT" in a code fence
)]

//! This crate wraps the openssl engine of the aziot-key-openssl-engine crate into a cdylib that can be loaded as a dynamic engine.
//!
//! This is not used by the IS or CS since they use the static engine, but is intended for third-party applications like modules.

#[no_mangle]
unsafe extern "C" fn aziot_key_openssl_engine_shared_bind(
    e: *mut openssl_sys::ENGINE,
    _id: *const std::os::raw::c_char,
) -> std::os::raw::c_int {
    let result = r#catch(Some(|| Error::ENGINE_BIND), || {
        aziot_key_openssl_engine::register(e, engine_init)?;
        Ok(())
    });
    match result {
        Ok(()) => 1,
        Err(()) => 0,
    }
}

unsafe extern "C" fn engine_init(e: *mut openssl_sys::ENGINE) -> std::os::raw::c_int {
    let result = r#catch(Some(|| Error::ENGINE_INIT), || {
        let key_connector: http_common::Connector = "unix:///run/aziot/keyd.sock"
            .parse()
            .expect("hard-coded URI must parse successfully");
        let key_client = aziot_key_client::Client::new(
            aziot_key_common_http::ApiVersion::V2020_09_01,
            key_connector,
        );
        let key_client = std::sync::Arc::new(key_client);

        aziot_key_openssl_engine::init(e, key_client)?;

        Ok(())
    });
    match result {
        Ok(()) => 1,
        Err(()) => 0,
    }
}

openssl_errors::openssl_errors! {
    #[allow(clippy::empty_enum)] // Workaround for https://github.com/sfackler/rust-openssl/issues/1189
    library Error("aziot_key_openssl_engine_shared") {
        functions {
            ENGINE_BIND("aziot_key_engine_shared_bind");
            ENGINE_INIT("aziot_key_engine_shared_init");
        }

        reasons {
            MESSAGE("");
        }
    }
}

/// Catches the error, if any, from evaluating the given callback and converts it to a unit sentinel.
/// If an openssl error function reference is provided, it is used to push the error onto the openssl error stack.
/// Otherwise, the error is logged to stderr.
///
/// Intended to be used at FFI boundaries, where a Rust error cannot pass through and must be converted to an integer, nullptr, etc.
fn r#catch<T>(
    function: Option<fn() -> openssl_errors::Function<Error>>,
    f: impl FnOnce() -> Result<T, Box<dyn std::error::Error>>,
) -> Result<T, ()> {
    match f() {
        Ok(value) => Ok(value),
        Err(err) => {
            // Technically, the order the errors should be put onto the openssl error stack is from root cause to top error.
            // Unfortunately this is backwards from how Rust errors work, since they are top error to root cause.
            //
            // We could do it the right way by collect()ing into a Vec<&dyn Error> and iterating it backwards,
            // but it seems too wasteful to be worth it. So just put them in the wrong order.

            if let Some(function) = function {
                openssl_errors::put_error!(function(), Error::MESSAGE, "{}", err);
            } else {
                eprintln!("[aziot-key-openssl-engine-shared] error: {}", err);
            }

            let mut source = err.source();
            while let Some(err) = source {
                if let Some(function) = function {
                    openssl_errors::put_error!(function(), Error::MESSAGE, "{}", err);
                } else {
                    eprintln!("[aziot-key-openssl-engine-shared] caused by: {}", err);
                }

                source = err.source();
            }

            Err(())
        }
    }
}
