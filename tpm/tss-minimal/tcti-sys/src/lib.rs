#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
// https://github.com/rust-lang/rust-bindgen/issues/1651
#![cfg_attr(test, allow(deref_nullptr))]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
