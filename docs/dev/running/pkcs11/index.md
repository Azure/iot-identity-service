# Setting up your PKCS#11 library

Follow the steps corresponding to your hardware:

- `softhsm2`: A software-emulated HSM. Requires no hardware.
- `cryptoauthlib`: A library for Microchip devices like the ATECC608A.
- `tpm2-pkcs11`: A library for all TPM 2.0 devices.


1. Install and configure

    - `softhsm2`: [Link](softhsm2.md)
    - `cryptoauthlib`: [Link](cryptoauthlib.md)
    - `tpm2-pkcs11`: [Link](tpm2-pkcs11/index.md)

1. Define variables to identify the PKCS#11 token.

    - `softhsm2`

        ```sh
        # Path of the PKCS#11 library
        export PKCS11_LIB_PATH='/usr/lib64/pkcs11/libsofthsm2.so'
        # export PKCS11_LIB_PATH='/usr/lib/arm-linux-gnueabihf/softhsm/libsofthsm2.so'

        # Variables to identify and log in to the PKCS#11 token
        TOKEN='Key pairs'
        TOKEN_PARAM="token=$TOKEN"
        PIN='1234'
        PIN_SUFFIX="?pin-value=$PIN"
        ```

    - `cryptoauthlib`

        ```sh
        # Path of the PKCS#11 library
        export PKCS11_LIB_PATH='/usr/lib/libcryptoauth.so'

        # Variables to identify and log in to the PKCS#11 token
        TOKEN_PARAM='slot-id=0'
        PIN_SUFFIX=''
        ```

    - `tpm2-pkcs11`

        ```sh
        # Path of the PKCS#11 library
        export PKCS11_LIB_PATH='/usr/local/lib/libtpm2_pkcs11.so'
        # export PKCS11_LIB_PATH='/usr/lib/arm-linux-gnueabihf/pkcs11/libtpm2_pkcs11.so'

        # Variables to identify and log in to the PKCS#11 token
        TOKEN='Key pairs'
        TOKEN_PARAM="token=$TOKEN"
        PIN='1234'
        PIN_SUFFIX="?pin-value=$PIN"
        ```

1. Clear existing keys.

    - `softhsm2`

        ```sh
        # This is the `directories.tokendir` in `softhsm2.conf`
        rm -rf /var/lib/softhsm/tokens/* &&
        softhsm2-util \
            --init-token --free \
            --label "$TOKEN" \
            --so-pin "so$PIN" --pin "$PIN"
        ```

    - `cryptoauthlib`

        ```sh
        # This is the directory specified by `filestore`
        # in `cryptoauthlib.conf`, plus the metadata files
        # for objects in PKCS#11 slot 0.
        rm -f /var/lib/cryptoauthlib/0.*.conf
        ```

    - `tpm2-pkcs11`

        ```sh
        sudo tpm2_clear

        # This is the directory tpm2-pkcs11 was
        # configured to use.
        export TPM2_PKCS11_STORE='/opt/tpm2-pkcs11'

        # tpm2_ptool requires Python 3 >= 3.7 and expects `python3`
        # to be that version by default.
        #
        # If your distro has python3.7 or higher at a different path,
        # like how Ubuntu 18.04 has `python3.7`, then set
        # the `PYTHON_INTERPRETER` env var.
        #
        # export PYTHON_INTERPRETER=python3.7

        rm -f "$TPM2_PKCS11_STORE/tpm2_pkcs11.sqlite3"
        (
            cd ~/src/tpm2-pkcs11/tools &&
            ./tpm2_ptool init --primary-auth '1234' &&
            ./tpm2_ptool addtoken \
                --sopin "so$PIN" --userpin "$PIN" \
                --label "$TOKEN" --pid '1'
        )
        ```

The hardware and PKCS#11 library has now been configured.

To test with `pkcs11-tool`, run `pkcs11-tool --module "$PKCS11_LIB_PATH" ...`. For example, `pkcs11-tool --module "$PKCS11_LIB_PATH" -T` will show information about the "Key pairs" token that was created above.

To test it with `p11tool`, run `p11tool --provider "$PKCS11_LIB_PATH" ...`. For example, `p11tool --provider="$PKCS11_LIB_PATH" --list-token-urls` will show the token URL for the "Key pairs" token that was created above.

Another alternative for `p11tool` is to create a `.module` file so that you don't need to pass in `--provider` for every invocation:

```sh
sudo mkdir -p /etc/pkcs11/modules
<<< "module: $PKCS11_LIB_PATH" sudo tee /etc/pkcs11/modules/tpm2-pkcs11.module
```

However, `--provider` is still useful to filter out tokens from other PKCS#11 libraries.


---


## Testing with aziot-keyd

To verify your HSM and its PKCS#11 library with aziot-keyd, see [Testing the openssl engine.](../aziot-keyd.md#testing-the-openssl-engine)

If the script mentioned there completes successfully, then the hardware and PKCS#11 library ought to be suitable for `aziot-keyd` to use. If there are errors such as crashes or signature verification failures, then it might be a problem with the hardware configuration, a bug in the PKCS#11 library, or a bug in the PKCS#11-related code in this repository.
