// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

fn main() {
    println!("cargo:rerun-if-changed=build/engine.c");

    openssl_build::define_version_number_cfg();

    let mut build = openssl_build::get_c_compiler();
    build
        // Since we are going to use the generated archive in a shared
        // library, we need +whole-archive to be set.  See:
        // https://github.com/rust-lang/rust/blob/1.61.0/RELEASES.md#compatibility-notes
        .cargo_metadata(false)
        .file("build/engine.c")
        .compile("aziot_key_openssl_shared_engine_wrapper");

    println!("cargo:rustc-link-lib=static:+whole-archive=aziot_key_openssl_shared_engine_wrapper");
    println!(
        "cargo:rustc-link-search=native={}",
        std::env::var("OUT_DIR").unwrap()
    );
}
