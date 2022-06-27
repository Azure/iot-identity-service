// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    clippy::missing_safety_doc,
    clippy::unreadable_literal
)]
#![cfg_attr(test, allow(clippy::too_many_lines))]
// https://github.com/rust-lang/rust-bindgen/pull/2230
#![cfg_attr(test, allow(clippy::items_after_statements))]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    // Check for presence
    #[allow(unused_imports)]
    use super::{DEF_TPM2_HR_PERSISTENT, DEF_TPM2_SE_HMAC, DEF_TPM2_SE_POLICY, DEF_TPM2_SE_TRIAL};
}
