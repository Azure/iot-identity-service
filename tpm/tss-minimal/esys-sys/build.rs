// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-env-changed=VENDOR_PREFIX");
    println!("cargo:rerun-if-env-changed=VENDOR_PKGCONFIG");

    if let Some((fakeroot, pkgconfig)) =
        std::env::var_os("VENDOR_PREFIX").zip(std::env::var_os("VENDOR_PKGCONFIG"))
    {
        if std::path::Path::new(&fakeroot).exists() {
            std::env::set_var("PKG_CONFIG_SYSROOT_DIR", fakeroot);
            std::env::set_var("PKG_CONFIG_PATH", pkgconfig);
        }
    }

    let lib_cfg = pkg_config::Config::new()
        .atleast_version("2.1.0") // Esys_Free introduction
        .probe("tss2-esys")
        .unwrap();

    for lib in lib_cfg.libs {
        println!("cargo:rustc-link-lib={}", lib);
    }

    for path in lib_cfg.link_paths {
        println!("cargo:rustc-link-search={}", path.to_str().unwrap());
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .allowlist_function("Esys_ActivateCredential")
        .allowlist_function("Esys_Create")
        .allowlist_function("Esys_CreatePrimary")
        .allowlist_function("Esys_EvictControl")
        .allowlist_function("Esys_Finalize")
        .allowlist_function("Esys_FlushContext")
        .allowlist_function("Esys_Free")
        .allowlist_function("Esys_GetTcti")
        .allowlist_function("Esys_HMAC")
        .allowlist_function("Esys_HMAC_Start")
        .allowlist_function("Esys_Import")
        .allowlist_function("Esys_Initialize")
        .allowlist_function("Esys_Load")
        .allowlist_function("Esys_PolicyGetDigest")
        .allowlist_function("Esys_PolicySecret")
        .allowlist_function("Esys_ReadPublic")
        .allowlist_function("Esys_SequenceComplete")
        .allowlist_function("Esys_SequenceUpdate")
        .allowlist_function("Esys_StartAuthSession")
        .allowlist_function("Esys_TR_FromTPMPublic")
        .allowlist_function("Esys_TR_SetAuth")
        .allowlist_var("ESYS_TR_.*")
        .blocklist_type("TPM.*")
        .blocklist_type("TSS2_TCTI_CONTEXT")
        .blocklist_type("TSS2_TCTI_OPAQUE_CONTEXT_BLOB")
        .clang_args(
            lib_cfg
                .include_paths
                .into_iter()
                .map(|path| format!("-I{}", path.to_str().unwrap())),
        )
        .generate()
        .unwrap();

    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();
}
