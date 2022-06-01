#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
