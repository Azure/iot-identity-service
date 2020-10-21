// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::let_and_return,
    clippy::missing_errors_doc,
    clippy::shadow_unrelated,
    clippy::use_self
)]

//! This crate implements a custom openssl engine that implements the openssl engine and key methods API in terms of PKCS#11.
//!
//! To use the engine, obtain a [`pkcs11::Context`] and call [`load`]

// Note: The majority of the code in this crate is code that is called from openssl. Because of the provenance of data that comes from openssl
// cannot be verified, the inputs to the functions cannot be guaranteed to be safe to work with.
//
// For example, there is no way to be sure that a buffer passed in by openssl with a particular pointer and a length is actually that long.
// So even after the buffer is converted to a slice, it is not safe to then drop out of `unsafe` and use that slice. The only choice is to trust openssl
// that the buffer really is that long, and to remain under `unsafe` to indicate that safety is not guaranteed.
//
// As a result, the majority of the code in this crate is marked `unsafe`.

mod ec_key;

mod engine;

pub(crate) mod ex_data;

mod rsa;

/// Load a new instance of the PKCS#11 openssl engine for the given PKCS#11 context.
pub fn load(
    context: std::sync::Arc<pkcs11::Context>,
) -> Result<openssl2::FunctionalEngine, openssl2::Error> {
    unsafe { engine::Engine::load(context) }
}

openssl_errors::openssl_errors! {
    #[allow(clippy::empty_enum)] // Workaround for https://github.com/sfackler/rust-openssl/issues/1189
    library Error("pkcs11_openssl_engine") {
        functions {
            ENGINE_LOAD_PRIVKEY("pkcs11_engine_load_privkey");
            ENGINE_LOAD_PUBKEY("pkcs11_engine_load_pubkey");

            ENGINE_PKEY_METHS("pkcs11_engine_pkey_meths");

            PKCS11_EC_SIGN("pkcs11_ec_sign");

            PKCS11_RSA_PRIV_ENC("pkcs11_rsa_priv_enc");
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
                eprintln!("[pkcs11-openssl-engine] error: {}", err);
            }

            let mut source = err.source();
            while let Some(err) = source {
                if let Some(function) = function {
                    openssl_errors::put_error!(function(), Error::MESSAGE, "{}", err);
                } else {
                    eprintln!("[pkcs11-openssl-engine] caused by: {}", err);
                }

                source = err.source();
            }

            Err(())
        }
    }
}
