// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

fn main() {
    #[cfg(feature = "vendor")]
    {
        let tpm2_tss_root = std::path::PathBuf::from(std::env::var("DEP_TPM2_TSS_ROOT").unwrap());
        std::env::set_var("PKG_CONFIG_PATH", tpm2_tss_root.join("lib").join("pkgconfig"));
    }
    let lib_cfg = pkg_config::Config::new()
        .atleast_version("2.1.0") // Esys_Free introduction
        .probe("tss2-esys")
        .unwrap();

    println!("cargo:rerun-if-changed=wrapper.h");

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
