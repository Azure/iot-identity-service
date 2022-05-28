#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    // Check for presence
    #[allow(unused_imports)]
    use super::{DEF_TPM2_HR_PERSISTENT, DEF_TPM2_SE_HMAC, DEF_TPM2_SE_POLICY, DEF_TPM2_SE_TRIAL};
}
