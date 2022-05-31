fn main() {
    let lib_cfg = pkg_config::Config::new()
        .atleast_version("2.0.0") // tss2-mu introduction
        .probe("tss2-mu")
        .unwrap();

    println!("cargo:rerun-if-changed=wrapper.h");

    for lib in lib_cfg.libs {
        println!("cargo:rustc-link-lib={}", lib);
    }

    for path in lib_cfg.link_paths {
        println!("cargo:rustc-link-path={}", path.to_str().unwrap());
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .allowlist_function("Tss2_MU_TPM2B_PUBLIC_Marshal")
        .allowlist_function("Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal")
        .allowlist_function("Tss2_MU_TPM2B_ID_OBJECT_Unmarshal")
        .allowlist_function("Tss2_MU_TPM2B_PRIVATE_Unmarshal")
        .allowlist_function("Tss2_MU_TPM2B_PUBLIC_Unmarshal")
        .allowlist_function("Tss2_MU_UINT16_Unmarshal")
        .blocklist_type("TPM.*")
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
