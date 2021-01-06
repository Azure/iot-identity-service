# Building the services

1. Clone this repo.

    ```sh
    git clone --recursive https://github.com/Azure/iot-identity-service
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

1. Install [`rustup`](https://rustup.rs). Ensure that `~/.cargo/bin` is in `$PATH`. The exact toolchain used to build this repository will automatically be downloaded later if necessary.

1. Install `bindgen` and `cbindgen`. Again, check [`/ci/install-build-deps.sh`](../ci/install-build-deps.sh) for the exact command and versions.

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

    Then export an env var to tell `bindgen` (and in turn, libclang) about this directory.

    ```sh
    export BINDGEN_EXTRA_CLANG_ARGS='-isystem /usr/lib/gcc/x86_64-linux-gnu/7/include-fixed'
    ```

    Then invoke `make` again.
