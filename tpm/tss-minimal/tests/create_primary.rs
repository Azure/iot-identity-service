// Copyright (c) Microsoft. All rights reserved.

#[test]
fn create_primary() -> tss_minimal::Result<()> {
    _ = env_logger::builder().is_test(true).try_init();

    let ctx = tss_minimal::EsysContext::new(&std::ffi::CString::default())?;

    let sensitive = unsafe { std::mem::zeroed() };
    let _handle = ctx.create_primary(
        &tss_minimal::Persistent::PASSWORD_SESSION,
        tss_minimal::Persistent::ENDORSEMENT_HIERARCHY,
        &sensitive,
        &tss_minimal::types::EK_RSA_TEMPLATE,
        None,
    )?;

    Ok(())
}
