// Copyright (c) Microsoft. All rights reserved.

fn main() {
    openssl_build::define_version_number_cfg();

    let mut build = openssl_build::get_c_compiler();
    build
        .file("build/engine.c")
        .compile("aziot_key_openssl_engine_wrapper");
}
