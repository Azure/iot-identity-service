// Copyright (c) Microsoft. All rights reserved.

#[test]
#[ignore = "TODO: Investigate why this fails"]
fn from_tpm_public() -> tss_minimal::Result<()> {
    _ = env_logger::builder().is_test(true).try_init();

    let ctx = tss_minimal::EsysContext::new(&std::ffi::CString::default())?;

    let sensitive = unsafe { std::mem::zeroed() };
    let handle = ctx.create_primary(
        &tss_minimal::Persistent::PASSWORD_SESSION,
        tss_minimal::Persistent::ENDORSEMENT_HIERARCHY,
        &sensitive,
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
