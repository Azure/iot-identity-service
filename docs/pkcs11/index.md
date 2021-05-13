# Protecting keys via an HSM or TPM

The Keys Service stores cryptographic keys, and allows callers to perform operations with those keys like encrypt, decrypt and sign. The service protects the keys by storing them in HSMs, and ensures that no operations against those keys export the keys to the device's memory.

In order to interact with an HSM, the Keys Service requires a PKCS#11 library for the HSM. There are two properties that must be configured in the `/etc/aziot/config.toml` file:

```toml
[aziot_keys]
pkcs11_lib_path = "<path of the PKCS#11 library>"
pkcs11_base_slot = "<PKCS#11 URI of a slot where dynamically generated keys will be stored>"
```


## Installing and configuring a PKCS#11 library

- Any TPM 2.0 TPM can be accessed via the `tpm2-pkcs11` library. See [this page](tpm2-pkcs11.md) for details of how to install the library on your device.

- Microchip devices like the ATECC608A can be accessed via the `cryptoauthlib` library. See [this page](cryptoauthlib.md) for details of how to install the library on your device.

- (Not recommended for production) A software-simulated HSM can be accessed via the `softhsm` library. See [this page](softhsm.md) for details of how to install the library on your device. This library stores all keys on the filesystem, so it is only useful for development and testing, not for production.


## Verifying the PKCS#11 library was installed and configured correctly

After you've configured the PKCS#11 library, you can test it with `pkcs11-tool` or `p11tool`. Since the library has been configured for the Keys Service's `aziotks` Linux user, ensure that you always use that user when using `pkcs11-tool`, `p11tool`, etc. For example, prepend those commands with `sudo -u aziotks`.

(`$PKCS11_LIB_PATH` is the path of the PKCS#11 library that you set as the value of `aziot_keys.pkcs11_lib_path` in the `/etc/aziot/config.toml`)

- To test with `pkcs11-tool`, run `pkcs11-tool --module "$PKCS11_LIB_PATH" ...`. For example, `pkcs11-tool --module "$PKCS11_LIB_PATH" -IOT` will show information about the token and all objects in it.

- To test it with `p11tool`, run `p11tool --provider "$PKCS11_LIB_PATH" ...`. For example, `p11tool --provider="$PKCS11_LIB_PATH" --list-token-urls` will show the token URL for the token.

    Another alternative for `p11tool` is to create a `.module` file so that you don't need to pass in `--provider` for every invocation:

    ```sh
    sudo mkdir -p /etc/pkcs11/modules
    <<< "module: $PKCS11_LIB_PATH" sudo tee /etc/pkcs11/modules/tpm2-pkcs11.module
    ```

    However, `--provider` is still useful to filter out tokens from other PKCS#11 libraries.

The pages above tell you how to modify the `/etc/aziot/config.toml` with the details of the PKCS#11 library and the base slot.
