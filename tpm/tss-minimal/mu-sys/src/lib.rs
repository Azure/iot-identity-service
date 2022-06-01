#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
// https://github.com/rust-lang/rust-bindgen/issues/1651
#![cfg_attr(test, allow(deref_nullptr))]

use types_sys::{TPM2B_ENCRYPTED_SECRET, TPM2B_ID_OBJECT, TPM2B_PRIVATE, TPM2B_PUBLIC};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
