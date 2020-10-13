// Copyright (c) Microsoft. All rights reserved.

use std::env;
use std::path::Path;
use std::process::Command;

use cmake::Config;

const SSL_OPTION: &str = "use_openssl";
const USE_EMULATOR: &str = "use_emulator";

trait SetPlatformDefines {
    fn set_platform_defines(&mut self) -> &mut Self;
}

impl SetPlatformDefines for Config {
    fn set_platform_defines(&mut self) -> &mut Self {
        let rv = if env::var("TARGET").unwrap().starts_with("x86_64")
            && env::var("RUN_VALGRIND").is_ok()
        {
            "ON"
        } else {
            "OFF"
        };
        if let Ok(sysroot) = env::var("SYSROOT") {
            self.define("run_valgrind", rv)
                .define("CMAKE_SYSROOT", sysroot)
                .define(USE_EMULATOR, "OFF")
        } else {
            self.define("run_valgrind", rv).define(USE_EMULATOR, "OFF")
        }
    }
}

fn main() {
    // Clone Azure C -shared library
    let c_shared_repo = "azure-iot-hsm-c/deps/c-shared";
    let utpm_repo = "azure-iot-hsm-c/deps/utpm";

    println!("#Start Update C-Shared Utilities");
    if !Path::new(&format!("{}/.git", c_shared_repo)).exists()
        || !Path::new(&format!("{}/.git", utpm_repo)).exists()
    {
        let _ = Command::new("git")
            .arg("submodule")
            .arg("update")
            .arg("--init")
            .arg("--recursive")
            .status()
            .expect("submodule update failed");
    }

    println!("#Done Updating C-Shared Utilities");

    println!("#Start building shared utilities");
    let _shared = Config::new(c_shared_repo)
        .define(SSL_OPTION, "ON")
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("run_unittests", "OFF")
        .define("use_default_uuid", "ON")
        .define("use_http", "OFF")
        .define("skip_samples", "ON")
        .set_platform_defines()
        .define("run_valgrind", "OFF")
        .profile("Release")
        .build();

    println!("#Also build micro tpm library");
    let _shared = Config::new(utpm_repo)
        .define(SSL_OPTION, "ON")
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("run_unittests", "OFF")
        .define("use_default_uuid", "ON")
        .define("use_http", "OFF")
        .define("skip_samples", "ON")
        .set_platform_defines()
        .define("run_valgrind", "OFF")
        .profile("Release")
        .build();

    // make the C libary at azure-iot-hsm-c (currently a subdirectory in this
    // crate)
    // Always make the Release version because Rust links to the Release CRT.

    let rut = if env::var("FORCE_NO_UNITTEST").is_ok() {
        "OFF"
    } else {
        "ON"
    };
    println!("#Start building HSM dev-mode library");
    let iothsm = Config::new("azure-iot-hsm-c")
        .define(SSL_OPTION, "ON")
        .define("CMAKE_BUILD_TYPE", "Release")
        .define("run_unittests", rut)
        .define("use_default_uuid", "ON")
        .define("use_http", "OFF")
        .define("skip_samples", "ON")
        .set_platform_defines()
        .profile("Release")
        .build();

    println!("#Done building HSM dev-mode library");

    // where to find the library (The "link-lib" should match the library name
    // defined in the CMakefile.txt)

    println!("cargo:rerun-if-env-changed=RUN_VALGRIND");
    // For libraries which will just install in target directory
    println!("cargo:rustc-link-search=native={}", iothsm.display());
    // For libraries (ie. C Shared) which will install in $target/lib
    println!("cargo:rustc-link-search=native={}/lib", iothsm.display());
    println!("cargo:rustc-link-search=native={}/lib64", iothsm.display());
    println!("cargo:rustc-link-lib=iothsm");

    println!("cargo:rustc-link-lib=aziotsharedutil");
    println!("cargo:rustc-link-lib=utpm");

    #[cfg(target_os = "macos")]
    {
        println!(
            "cargo:rustc-link-search=native={}/lib",
            env::var("OPENSSL_ROOT_DIR").unwrap()
        );
    }

    #[cfg(unix)]
    println!("cargo:rustc-link-lib=crypto");
}
