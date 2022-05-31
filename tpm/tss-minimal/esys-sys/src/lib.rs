#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
// https://github.com/rust-lang/rust-bindgen/issues/1651
#![cfg_attr(test, allow(deref_nullptr))]

use tcti_sys::TSS2_TCTI_CONTEXT;
#[allow(unused_imports)]
// TPMI_RH_HIERARCHY is required on 2.3.2 (non-exhaustive)
use types_sys::TPMI_RH_HIERARCHY;
use types_sys::{
    TPM2B_AUTH, TPM2B_CREATION_DATA, TPM2B_DATA, TPM2B_DIGEST, TPM2B_ENCRYPTED_SECRET,
    TPM2B_ID_OBJECT, TPM2B_MAX_BUFFER, TPM2B_NAME, TPM2B_NONCE, TPM2B_PRIVATE, TPM2B_PUBLIC,
    TPM2B_SENSITIVE_CREATE, TPM2B_TIMEOUT, TPM2_HANDLE, TPM2_SE, TPMI_ALG_HASH, TPMI_DH_PERSISTENT,
    TPML_PCR_SELECTION, TPMT_SYM_DEF, TPMT_SYM_DEF_OBJECT, TPMT_TK_AUTH, TPMT_TK_CREATION,
    TPMT_TK_HASHCHECK,
};

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {
    // Check for presence
    #[allow(unused_imports)]
    use super::{
        ESYS_TR_NONE, ESYS_TR_PASSWORD, ESYS_TR_RH_ENDORSEMENT, ESYS_TR_RH_NULL, ESYS_TR_RH_OWNER,
        ESYS_TR_RH_PLATFORM,
    };
}
