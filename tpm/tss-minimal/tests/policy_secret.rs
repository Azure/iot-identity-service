// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

#[test]
fn main() -> tss_minimal::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let ctx = tss_minimal::EsysContext::new(&std::ffi::CString::default())?;
    let auth_session = tss_minimal::Persistent::PASSWORD_SESSION;

    let sym = types_sys::TPMT_SYM_DEF {
        algorithm: tss_minimal::types::sys::DEF_TPM2_ALG_AES,
        keyBits: tss_minimal::types::sys::TPMU_SYM_KEY_BITS { aes: 256 },
        mode: tss_minimal::types::sys::TPMU_SYM_MODE {
            aes: tss_minimal::types::sys::DEF_TPM2_ALG_CFB,
        },
    };

    let mut auth = ctx.start_auth_session(
        tss_minimal::types::sys::DEF_TPM2_SE_POLICY,
        &sym,
        tss_minimal::types::sys::DEF_TPM2_ALG_SHA256,
    )?;
    tss_minimal::Policy::new(
        tss_minimal::PolicyKind::Secret {
            handle: &tss_minimal::Persistent::ENDORSEMENT_HIERARCHY,
            auth: &auth_session,
        },
        &ctx,
    )
    .apply(&mut auth)?;

    let dgst = ctx.policy_digest(&auth)?;
    let expected: [u8; 32] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7,
        0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
        0x69, 0xAA,
    ];

    assert_eq!(expected, dgst.buffer[..dgst.size as _]);

    Ok(())
}
