// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

#[test]
fn main() -> tss_minimal::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let ctx = tss_minimal::EsysContext::new(&std::ffi::CString::default())?;

    let handle = ctx.create_primary(
        &tss_minimal::Persistent::PASSWORD_SESSION,
        tss_minimal::Persistent::ENDORSEMENT_HIERARCHY,
        unsafe { &std::mem::zeroed() },
        &tss_minimal::types::EK_RSA_TEMPLATE,
        None,
    )?;

    let _handle_persistent = ctx.evict(
        tss_minimal::Persistent::OWNER_HIERARCHY,
        &handle,
        &tss_minimal::Persistent::PASSWORD_SESSION,
        0x8101_0001,
    )?;

    let handle = ctx.from_tpm_public(0x8101_0001, None)?;

    let handle = ctx.evict(
        tss_minimal::Persistent::OWNER_HIERARCHY,
        &handle,
        &tss_minimal::Persistent::PASSWORD_SESSION,
        0,
    )?;

    assert!(handle.is_none());

    Ok(())
}
