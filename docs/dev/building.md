# Building the services

1. Clone this repo.

    ```sh
    git clone https://github.com/Azure/iot-identity-service
    cd iot-identity-service/
    ```

1. Install build dependencies.

    - `gcc`
    - `libclang1`
    - `llvm-config`
    - `make`
    - `openssl` headers and libraries
    - `pkg-config`

    Check [`/ci/install-build-deps.sh`](../ci/install-build-deps.sh) for the exact names of the packages for your distro that contain these components.

1. Install a stable toolchain of Rust. One can be easily installed via [`rustup`](https://rustup.rs). Ensure that `~/.cargo/bin` is in `$PATH`.

1. Install `bindgen` and `cbindgen`

    ```sh
    cargo install --force bindgen cbindgen
    ```

1. Build the services.

    ```sh
    make
    ```

    If the build fails with an error like:

    ```
    /usr/include/limits.h:124:16: fatal error: 'limits.h' file not found
    ```

    ... this is because `bindgen` got confused by the default `limits.h` that ships with `gcc`. Instead, you need to point it to an alternative one that doesn't use `include_next`. Find it with:

    ```sh
    find /usr/lib*/gcc/ -name limits.h | grep include-fixed
    ```

    This will print something like `/usr/lib/gcc/x86_64-linux-gnu/7/include-fixed/limits.h`

    Then invoke `make` with `BINDGEN_EXTRA_INCLUDE_DIR` set to the directory containing the `limits.h`:

    ```sh
    make BINDGEN_EXTRA_INCLUDE_DIR=/usr/lib/gcc/x86_64-linux-gnu/7/include-fixed/
    ```
