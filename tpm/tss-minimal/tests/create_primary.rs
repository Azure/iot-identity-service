#[test]
fn main() -> tss_minimal::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let ctx = tss_minimal::EsysContext::new(&std::ffi::CString::default())?;

    let _handle = ctx.create_primary(
        &tss_minimal::AuthSession::PASSWORD,
        tss_minimal::Hierarchy::ENDORSEMENT,
        unsafe { &std::mem::MaybeUninit::zeroed().assume_init() },
        &tss_minimal::types::EK_RSA_TEMPLATE,
        None,
    )?;

    Ok(())
}
