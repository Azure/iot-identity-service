// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]

fn main() {
    let mut build = openssl_build::get_c_compiler();
    build
        .file("build/pkcs7_to_x509.c")
        .compile("aziot_certd_pkcs7_to_x509");
}
