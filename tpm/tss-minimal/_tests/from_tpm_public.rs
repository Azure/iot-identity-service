// Copyright (c) Microsoft. All rights reserved.

#[test]
fn main() -> tss_minimal::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let ctx = tss_minimal::EsysContext::new(&std::ffi::CString::default())?;

    let handle = ctx.create_primary(
        &tss_minimal::AuthSession::PASSWORD,
        tss_minimal::Hierarchy::ENDORSEMENT,
        unsafe { &std::mem::MaybeUninit::zeroed().assume_init() },
        &tss_minimal::types::EK_RSA_TEMPLATE,
        None,
    )?;

    let _ = ctx.evict(
        tss_minimal::Hierarchy::OWNER,
        handle,
        &tss_minimal::AuthSession::PASSWORD,
        0x81010001,
    )?;

    let handle = ctx.from_tpm_public(0x81010001, None)?;

    let handle = ctx.evict(
        tss_minimal::Hierarchy::OWNER,
        handle,
        &tss_minimal::AuthSession::PASSWORD,
        0,
    )?;

    assert!(handle.is_none());

    Ok(())
}
