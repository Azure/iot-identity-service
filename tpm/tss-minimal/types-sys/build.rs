// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

fn main() {
    let lib_cfg = pkg_config::Config::new().probe("tss2-sys").unwrap();

    println!("cargo:rerun-if-changed=wrapper.h.in");
    println!("cargo:rerun-if-changed=const_define.sh");

    let out_path = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let wrapper = out_path.join("wrapper.h");

    for path in &lib_cfg.include_paths {
        if std::process::Command::new("./const_define.sh")
            .arg(path)
            .arg("TPM2_ALG:TPM2_ALG_ID,TPM2_ECC:TPM2_ALG_ID,TPM2_HR:TPM2_HC,TPM2_SE,TPMA_OBJECT,TPMA_SESSION")
            .stdout(std::fs::File::create(&wrapper).unwrap())
            .status()
            .unwrap()
            .success()
        {
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
