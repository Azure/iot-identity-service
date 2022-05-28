#[test]
fn main() -> tss_minimal::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let ctx = tss_minimal::EsysContext::new(&std::ffi::CString::new("swtpm:port=8181").unwrap())?;
    let auth_session = tss_minimal::AuthSession::PASSWORD;

    let hierarchy = tss_minimal::Hierarchy::ENDORSEMENT;
    // handle.set_auth(&ctx, b"foobar")?;

    let sym = types_sys::TPMT_SYM_DEF {
        algorithm: tss_minimal::types::sys::DEF_TPM2_ALG_AES,
        keyBits: tss_minimal::types::sys::TPMU_SYM_KEY_BITS { aes: 256 },
        mode: tss_minimal::types::sys::TPMU_SYM_MODE {
            aes: tss_minimal::types::sys::DEF_TPM2_ALG_CFB,
        },
    };

    let auth = ctx
        .start_auth_session(
            tss_minimal::SessionType::Policy,
            &sym,
            tss_minimal::types::sys::DEF_TPM2_ALG_SHA256,
        )?
        .with_policy(tss_minimal::Policy::new(
            tss_minimal::PolicyKind::Secret {
                handle: &hierarchy,
                auth: &auth_session,
            },
            &ctx,
        ))?;

    let dgst = ctx.policy_digest(&auth)?;
    let expected: [u8; 32] = [
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7,
        0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14,
        0x69, 0xAA,
    ];

    assert_eq!(expected, dgst.buffer[..dgst.size as _]);

    Ok(())
}
