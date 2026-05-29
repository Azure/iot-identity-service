// Copyright (c) Microsoft. All rights reserved.

fn main() {
    println!("cargo::rustc-link-lib=aziot_keys");

    let path = std::env::var_os("OUT_DIR").unwrap();
    let path = std::path::PathBuf::from(path);
    let path = path.parent().unwrap().parent().unwrap().parent().unwrap();
    println!("cargo::rustc-link-search={}", path.to_string_lossy());
}
