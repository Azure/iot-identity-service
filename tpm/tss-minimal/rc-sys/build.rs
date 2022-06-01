// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

fn main() {
    let lib_cfg = pkg_config::Config::new()
        .atleast_version("2.3.0") // tss2-rc introduction
        .probe("tss2-rc")
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
        .allowlist_function("Tss2_RC_Decode")
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
