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
        .atleast_version("2.0.0") // tss2-mu introduction
        .probe("tss2-mu")
        .unwrap();

    for lib in lib_cfg.libs {
        println!("cargo:rustc-link-lib={lib}");
    }

    for path in lib_cfg.link_paths {
        println!("cargo:rustc-link-search={}", path.to_str().unwrap());
    }

    let bindings = bindgen::Builder::default()
        .header("wrapper.h")
        .allowlist_function("Tss2_MU_TPM2B_PUBLIC_Marshal")
        .allowlist_function("Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal")
        .allowlist_function("Tss2_MU_TPM2B_ID_OBJECT_Unmarshal")
        .allowlist_function("Tss2_MU_TPM2B_PRIVATE_Unmarshal")
        .allowlist_function("Tss2_MU_TPM2B_PUBLIC_Unmarshal")
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
