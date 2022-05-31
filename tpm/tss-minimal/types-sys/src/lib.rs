#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]
// https://github.com/rust-lang/rust-bindgen/issues/1651
#![cfg_attr(test, allow(deref_nullptr))]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    // Check for presence
    #[allow(unused_imports)]
    use super::{DEF_TPM2_HR_PERSISTENT, DEF_TPM2_SE_HMAC, DEF_TPM2_SE_POLICY, DEF_TPM2_SE_TRIAL};
}
