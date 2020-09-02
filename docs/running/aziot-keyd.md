# Configuring and running `aziot-keyd`

A basic configuration looks like:

```toml
[aziot_keys]

[preloaded_keys]

[endpoints]
aziot_keyd = "unix:///var/lib/aziot/keyd.sock"
```

- `[aziot_keys]` - This section contains arbitrary key-value pairs of string type that are passed down to the `libaziot-keys.so` library. The names and values of these parameters depend on the library.

    When using Microsoft's library, the following parameters can be specified:

    - `homedir_path` - This is the home directory of the library, and where dynamically generated key files will be stored. Ensure that this directory exists, and that it is readable and writable by the user you will run the service as.

    - `pkcs11_lib_path` - This is the path of a PKCS#11 library.

    - `pkcs11_base_slot` - This is the `pkcs11:` URI of a PKCS#11 slot, and where dynamically generated keys will be stored. If the slot requires a PIN to create new keys or access private keys, this URI must have it set. Example: `pkcs11:token=Key pairs?pin-value=1234`

    Microsoft's implementation recognizes the following parameters:

    - `homedir_path`: The path of a directory under which dynamically created filesystem keys will be persisted.

    - `pkcs11_lib_path`: The path of a PKCS#11 library.

    - `pkcs11_base_slot`: The PKCS#11 URI of a slot under which dynamically created keys will be persisted.

    Depending on which of these parameters are set, the Keys Service has capabilities as follows:

    - Regardless of which of these parameters are set, the Keys Service will be able to access existing preloaded keys on the filesystem.

    - If `homedir_path` is set, the Keys Service will be able to persist new keys to the filesystem under the specified directory.

    - If `pkcs11_lib_path` is set, the Keys Service will be able to access preloaded keys using the specified PKCS#11 library.

    - If both `pkcs11_lib_path` and `pkcs11_base_slot` are set, the Keys Service will be able to persist new keys using the specified PKCS#11 library under the specified base slot.

- `[preloaded_keys]` - This section defines preloaded keys as a map of key ID to URI. For example, if you have a device ID cert file that you want the service to make available to the other components, you would register its private key file in this section.

    Only `file://` and `pkcs11:` URIs are supported at this time.

    For `file://` URIs, asymmetric keys must be in PEM format, and symmetric key must be in raw bytes format.

    For `pkcs11:` URIs, only the `object`, `slot-id`, `token` and `pin-value` parameters are supported. Note that the PKCS#11 objects will always be loaded using the library specified by the `pkcs11_lib_path` parameter, so using one PKCS#11 library for preloaded keys and another for dynamically generated keys is not possible.

- `[endpoints]` - This section defines endpoints for the services. For this service, there is only one endpoint:

    - The `aziot_keyd` value denotes the endpoint that this service will accept connections on.

    Endpoints can be `unix` URIs where the URI contains a path of a UDS socket that the service will bind to, or an `http` URI with a host (and optional port) that the service will bind a TCP socket to.

Assuming you're using Microsoft's implementation of `libaziot-keys.so`, start with this basic file and fill it out depending on what workflow you want to test:

1. Set `aziot_keys.homedir_path`

    ```toml
    [aziot_keys]
    homedir_path = "/var/lib/aziot/keyd"
    ```

1. If you want to use PKCS#11, you would have defined these variables as part of following the steps to configure your PKCS#11 library:

    - `$PKCS11_LIB_PATH`
    - `$TOKEN_PARAM`
    - `$PIN_SUFFIX`

    Set `aziot_keys.pkcs11_lib_path` parameter to `"$PKCS11_LIB_PATH"` and the `aziot_keys.pkcs11_base_slot` parameter to `"pkcs11:${TOKEN_PARAM}${PIN_SUFFIX}"`.

    For example, a config using `softhsm2` would look like:

    ```toml
    [aziot_keys]
    pkcs11_lib_path = "/usr/lib64/pkcs11/libsofthsm2.so"
    pkcs11_base_slot = "pkcs11:token=Key pairs?pin-value=1234"
    ```

    ... and a config using `cryptoauthlib` would look like:

    ```toml
    [aziot_keys]
    pkcs11_lib_path = "/usr/lib/libcryptoauth.so"
    pkcs11_base_slot = "pkcs11:slot-id=0"
    ```

1. Preload private keys for certs, corresponding to the auth method of the device identity:

    - If the device identity is set to use the `shared_private_key` auth method, there are not keys to be preloaded.

    - If the device identity is set to use the `x509_thumbprint` auth method, preload the private key of the device ID cert:

        ```toml
        [preloaded_keys]
        device-id = "file:///path/to/device-id.key.pem"
        ```

    - If the device identity is set to use the `x509_ca` auth method, preload the private key of the device ID CA cert:

        ```toml
        [preloaded_keys]
        device-id-ca = "file:///path/to/device-id-ca.key.pem"
        ```

    For `x509_thumbprint` and `x509_ca`, if the keys are backed by hardware, use a `pkcs11:` URI instead of a `file://` URI.

1. Save this file to any location that is readable by the user you will run the service as. The service looks for this file by default at `/etc/aziot/keyd/config.toml`, but it can be given a different path by setting the `AZIOT_KEYD_CONFIG` env var.

1. If you're using PKCS#11 and specifically the `tpm2-pkcs11` library, remember to also export the `TPM2_PKCS11_STORE` env var.

    ```sh
    export TPM2_PKCS11_STORE=/opt/tpm2-pkcs11
    ```

1. Run the service, setting the `AZIOT_KEYD_CONFIG` env var if necessary.

    ```sh
    export AZIOT_KEYD_CONFIG='...'

    cargo run -p aziot-keyd
    ```

    The service will remain running.
