// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

use std::io::Write;

fn main() {
    println!("cargo:rerun-if-changed=wrapper.h.in");
    println!("cargo:rerun-if-changed=const_define.sh");
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

    let lib_cfg = pkg_config::Config::new().probe("tss2-sys").unwrap();

    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let wrapper = out_path.join("wrapper.h");

    for path in &lib_cfg.include_paths {
        let output = std::process::Command::new("./const_define.sh")
            .arg(path)
            .arg("TPM2_ALG:TPM2_ALG_ID,TPM2_ECC:TPM2_ECC_CURVE,TPM2_HR:TPM2_HC,TPM2_SE,TPMA_OBJECT,TPMA_SESSION")
            .stderr(std::process::Stdio::inherit())
            .output()
            .unwrap();
        if output.status.success() {
            std::fs::File::create(&wrapper)
                .unwrap()
                .write_all(&output.stdout)
                .unwrap();
            break;
        }
    }

    let bindings = bindgen::Builder::default()
        .header(wrapper.to_str().unwrap())
        .clang_args(
            lib_cfg
                .include_paths
                .into_iter()
                .map(|path| format!("-I{}", path.to_str().unwrap())),
        )
        .generate()
        .unwrap();

    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .unwrap();
}
