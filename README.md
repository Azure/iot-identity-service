Prototype of libiothsm v2


# Build

1. Install build dependencies

    ## Ubuntu 18.04

    ```sh
    apt install \
        gcc make pkg-config \
        libclang1 llvm \
        libssl-dev
    ```

1. Install Rust

1. Install `bindgen` and `cbindgen`

    ```sh
    cargo install --force bindgen cbindgen
    ```

1. Clone this repo

    ```sh
    cd ~/src/
    git clone https://github.com/arsing/libiothsm2
    ```

1. Clone the openssl-pkcs11-demo repo

    ```sh
    cd ~/src/
    git clone https://github.com/arsing/openssl-pkcs11-demo
    ```

1. Build the code

    ```sh
    cd ~/src/libiothsm2/
    make
    ```

    If the build complains about `limits.h` and fails with:

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


# Run

1. Start `ksd`

    ```sh
    # HOMEDIR_PATH is a directory where key files will be stored.
    export HOMEDIR_PATH=~/iotedge/hsm/keys
    mkdir -p "$HOMEDIR_PATH"

    # Optionally enable PKCS#11 support by setting PKCS11_LIB_PATH and PKCS11_BASE_SLOT.
    # PKCS11_LIB_PATH is the path to a PKCS#11 library, and PKCS11_BASE_SLOT is the PKCS#11 URI of a slot that will be used to store new keys.
    #
    # export PKCS11_LIB_PATH=/usr/lib64/pkcs11/libsofthsm2.so
    # export PKCS11_BASE_SLOT='pkcs11:token=Key pairs?pin-value=1234'

    cargo run -p ksd # The server will remain running.
    ```

1. Run `iotedged` in another shell

    ```sh
    # HOMEDIR_PATH is a directory where cert files will be stored.
    export HOMEDIR_PATH=~/iotedge/hsm/certs
    mkdir -p "$HOMEDIR_PATH"

    # HUB_ID, DEVICE_ID and SAS_KEY are the IoT Hub name, device name and SAS key of an existing Azure IoT device.
    export HUB_ID='example.azure-devices.net'
    export DEVICE_ID='example-1'
    export SAS_KEY='QXp1cmUgSW9UIEVkZ2U='

    cargo run -p iotedged
    ```

`iotedged` should connect to `ksd` and:

- Create a self-signed device CA cert.
- Create a workload CA cert signed by the device CA cert.
- Import the IoT Hub SAS key to the Keys Service.
- Connect to the IoT Hub and perform a list modules HTTP request. The SAS token for this request is signed using the SAS key imported into the Keys Service.


# License

MIT
