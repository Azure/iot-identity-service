// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

fn main() {
    println!("cargo:rustc-link-lib=aziot_keys");
}
