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

    # If device identity is set to `x509_ca` or `x509_thumbprint`, and thus the IoT Hub connection would use a device ID client cert,
    # set the env var to preload the key in aziot-keyd
    #
    # env 'PRELOADED_KEY:device-id=file:///path/to/key.pem' cargo run -p aziot-keyd
    #
    # Otherwise, run it without that env var
    cargo run -p aziot-keyd # The server will remain running.
    ```

1. Start `aziot-certd` in another shell

    ```sh
    # HOMEDIR_PATH is a directory where cert files will be stored.
    export HOMEDIR_PATH=~/iotedge/hsm/certs
    mkdir -p "$HOMEDIR_PATH"

    # If device identity is set to `x509_ca` or `x509_thumbprint`, and thus the IoT Hub connection would use a device ID client cert,
    # set the env var to preload the cert in aziot-certd
    #
    # env 'PRELOADED_CERT:device-id=/path/to/cert.pem' cargo run -p aziot-certd
    #
    # Otherwise, run it without that env var
    cargo run -p aziot-certd # The server will remain running.
    ```

1. Run `iotedged` in a third shell

    ```sh
    # HUB_ID, DEVICE_ID and SAS_KEY are the IoT Hub name, device name and SAS key of an existing Azure IoT device.
    export HUB_ID='example.azure-devices.net'
    export DEVICE_ID='example-1'

    # If device identity is set to `shared_private_key`, set an env var for the SAS key.
    # Otherwise, leave it unset and iotedged will use the key and cert named "device-id" that you preloaded into aziot-keyd and aziot-certd respectively.
    export SAS_KEY='QXp1cmUgSW9UIEVkZ2U='

    cargo run -p iotedged
    ```

`iotedged` should connect to `aziot-keyd` and `aziot-certd`:

- Create a self-signed device CA cert.
- Create a workload CA cert signed by the device CA cert.
- If `SAS_KEY` is set:
    - Import the IoT Hub SAS key into `aziot-keyd`
    - Connect to the IoT Hub and perform a list modules HTTP request. The SAS token for this request is signed using the SAS key imported into `aziot-keyd`
- If `SAS_KEY` is not set:
    - Connect to the IoT Hub and perform a list modules HTTP request. The "device-id" key and cert preloaded into `aziot-keyd` and `aziot-certd` respectively are used for the TLS client certificate.


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
