// Copyright (c) Microsoft. All rights reserved.

#![expect(
    nonstandard_style,
    clippy::pub_underscore_fields,
    clippy::unreadable_literal
)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    // Check for presence
    #[allow(unused_imports)]
    use super::{DEF_TPM2_HR_PERSISTENT, DEF_TPM2_SE_HMAC, DEF_TPM2_SE_POLICY, DEF_TPM2_SE_TRIAL};
}
