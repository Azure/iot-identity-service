// Copyright (c) Microsoft. All rights reserved.

#[test]
fn main() -> tss_minimal::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let ctx = tss_minimal::EsysContext::new(&std::ffi::CString::default())?;

    let _handle = ctx.create_primary(
        &tss_minimal::Persistent::PASSWORD_SESSION,
        tss_minimal::Persistent::ENDORSEMENT_HIERARCHY,
        unsafe { &std::mem::zeroed() },
        &tss_minimal::types::EK_RSA_TEMPLATE,
        None,
    )?;

    Ok(())
}
