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
    git clone https://github.com/Azure/iot-identity-service
    ```

1. Build the code

    ```sh
    cd ~/src/iot-identity-service/
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

1. Start `aziot-keyd` in one shell

    ```sh
    # HOMEDIR_PATH is a directory where key files will be stored.
    export HOMEDIR_PATH=~/iotedge/hsm/keys
    mkdir -p "$HOMEDIR_PATH"

    # Optionally enable PKCS#11 support by setting PKCS11_LIB_PATH and PKCS11_BASE_SLOT.
    # PKCS11_LIB_PATH is the path to a PKCS#11 library, and PKCS11_BASE_SLOT is the PKCS#11 URI of a slot that will be used to store new keys.
    #
    # export PKCS11_LIB_PATH=/usr/lib64/pkcs11/libsofthsm2.so
    # export PKCS11_BASE_SLOT='pkcs11:token=Key pairs?pin-value=1234'
    ```

    - If device identity is set to `shared_private_key`, run the service normally:

        ```sh
        cargo run -p aziot-keyd
        ```

    - If device identity is set to `x509_ca` or `x509_thumbprint` auth method, the IoT Hub connection would use a device ID client cert.

        Either create a device ID cert and preload it into `aziot-keyd`:

        ```sh
        env 'PRELOADED_KEY:device-id=file:///path/to/key.pem' cargo run -p aziot-keyd
        ```

        ... or create a device ID CA cert and preload it into `aziot-keyd`:

        ```sh
        env 'PRELOADED_KEY:device-id-ca=file:///path/to/key.pem' cargo run -p aziot-keyd
        ```

    The server will remain running.

1. Start `aziot-certd` in another shell

    ```sh
    # HOMEDIR_PATH is a directory where cert files will be stored.
    export HOMEDIR_PATH=~/iotedge/hsm/certs
    mkdir -p "$HOMEDIR_PATH"
    ```

    - If device identity is set to `shared_private_key`, run the service normally:

        ```sh
        cargo run -p aziot-certd
        ```

    - If device identity is set to `x509_ca` or `x509_thumbprint` auth method, the IoT Hub connection would use a device ID client cert.

        Either create a device ID cert and preload it into `aziot-certd`:

        ```sh
        env 'PRELOADED_CERT:device-id=/path/to/cert.pem' cargo run -p aziot-certd
        ```

        ... or create a device ID CA cert and preload it into `aziot-certd`:

        ```sh
        env 'PRELOADED_CERT:device-id-ca=/path/to/cert.pem' cargo run -p aziot-certd
        ```

    The server will remain running.

1. Run `iotedged` in a third shell

    - If device identity is set to `shared_private_key`, run the program with the SAS key:

        ```sh
        cargo run -p iotedged -- --hub-id 'example.azure-devices.net' --device-id 'example-1' --sas-key 'QXp1cmUgSW9UIEVkZ2U='
        ```

    - If device identity is set to `x509_ca` or `x509_thumbprint` auth method, the IoT Hub connection would use a device ID client cert.

        Either run the program with the device ID cert:

        ```sh
        # The value of `--preloaded-device-id-cert` matches the name of the `PRELOADED_KEY:` and `PRELOADED_CERT:` env vars set above.
        cargo run -p iotedged -- --hub-id 'example.azure-devices.net' --device-id 'example-1' --preloaded-device-id-cert 'device-id'
        ```

        ... or create a device ID CA cert and preload it into `aziot-certd`:

        ```sh
        # The value of `--preloaded-device-id-ca-cert` matches the name of the `PRELOADED_KEY:` and `PRELOADED_CERT:` env vars set above.
        cargo run -p iotedged -- --hub-id 'example.azure-devices.net' --device-id 'example-1' --preloaded-device-id-ca-cert 'device-id-ca'
        ```

`iotedged` should connect to `aziot-keyd` and `aziot-certd`:

- Create a self-signed device CA cert.
- Create a workload CA cert signed by the device CA cert.
- When `--sas-key` is provided:
    - Import the IoT Hub SAS key into `aziot-keyd`
    - Connect to the IoT Hub and perform a list modules HTTP request. The SAS token for this request is signed using the SAS key imported into `aziot-keyd`
- When `--preloaded-device-id-cert` is provided:
    - Connect to the IoT Hub and perform a list modules HTTP request. The key and cert preloaded into `aziot-keyd` and `aziot-certd` respectively are used for the TLS client certificate.
- When `--preloaded-device-id-ca-cert` is provided:
    - Create a new device ID certificate using `aziot-certd` that is signed by the device ID CA cert whose ID is specified by the parameter. The CA cert's key and cert are obtained from `aziot-keyd` and `aziot-certd` respectively.
    - Connect to the IoT Hub and perform a list modules HTTP request. The device ID cert created in the previous step is used for the TLS client certificate.


# Miscellaneous

## Create IoT Device identity with X.509-CA auth mode

```sh
IOT_HUB_NAME=example
IOT_DEVICE_ID=example-1

# Certs will be stored here
mkdir -p ~/iotedge/scratch
cd ~/iotedge/scratch

# Create self-signed root CA
rm -f device-id-root.key.pem device-id-root.pem
openssl req -x509 -newkey rsa:4096 -keyout device-id-root.key.pem -out device-id-root.pem -days 365 -nodes

# Upload root CA to IoT Hub
az iot hub certificate create --hub-name "$IOT_HUB_NAME" --name device-id-root --path "$PWD/device-id-root.pem"

# Generate first etag for verification code request
etag="$(az iot hub certificate show --hub-name "$IOT_HUB_NAME" --name device-id-root --query etag --output tsv)"

# Generate verification code and also save new etag
cloud_certificate="$(az iot hub certificate generate-verification-code --hub-name "$IOT_HUB_NAME" --name device-id-root --etag "$etag")"
etag="$(<<< "$cloud_certificate" jq '.etag' -r)"
verification_code="$(<<< "$cloud_certificate" jq '.properties.verificationCode' -r)"

# Print the verification code. This becomes the CN of the verification cert.
echo $verification_code

# Generate CSR for verification cert and sign it with the root CA to get the verification cert.
#
# Set CN to `$verificationCode` (printed above) when prompted.
rm -f device-id-root-verify.key.pem device-id-root-verify.csr device-id-root-verify.pem
openssl req -newkey rsa:2048 -keyout device-id-root-verify.key.pem -out device-id-root-verify.csr -days 1 -nodes
openssl x509 -req -in device-id-root-verify.csr -CA device-id-root.pem -CAkey device-id-root.key.pem -out device-id-root-verify.pem -days 365 -CAcreateserial

# Upload verification cert to IoT Hub
az iot hub certificate verify --hub-name "$IOT_HUB_NAME" --name device-id-root --path $PWD/device-id-root-verify.pem --etag "$etag"

# Clean up verification cert
rm -f device-id-root-verify.key.pem device-id-root-verify.csr device-id-root-verify.pem

# Create device identity with X.509-CA auth mode
az iot hub device-identity create --hub-name "$IOT_HUB_NAME" --device-id "$IOT_DEVICE_ID" --auth-method x509_ca

# Generate CSR for device ID cert and sign it with the root CA to get the device ID cert.
rm -f device-id.key.pem device-id.csr device-id.pem
openssl req -newkey rsa:2048 -keyout device-id.key.pem -out device-id.csr -days 1 -nodes
openssl x509 -req -in device-id.csr -CA device-id-root.pem -CAkey device-id-root.key.pem -out device-id.pem -days 365 -CAcreateserial

# Clean up device ID CSR
rm -f device-id.csr
```


# License

MIT


# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
