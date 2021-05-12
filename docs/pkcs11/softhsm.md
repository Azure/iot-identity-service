# Installing and configuring the `softhsm` library

`softhsm2` is a PKCS#11 library that emulates an HSM entirely in software. It implements key operations using `openssl`.

Since the keys are stored on the filesystem, this PKCS#11 library is not recommended to be used in production. It is only an option for development and testing without actual hardware.

1. Install `softhsm2`. The library is present in most distro's repositories already.

    ```sh
    sudo apt install -y softhsm2
    ```

1. The `softhsm2` configuration and filesystem directory is ACLed to the `softhsm` group. The Keys Service's user `aziotks` must be added to this group.

    ```sh
    sudo usermod -aG softhsm aziotks
    ```

1. The `softhsm2` configuration is at `/etc/softhsm/softhsm2.conf` and looks like:

    ```
    # SoftHSM v2 configuration file

    directories.tokendir = /var/lib/softhsm/tokens/
    objectstore.backend = file

    # ERROR, WARNING, INFO, DEBUG
    log.level = ERROR

    # If CKF_REMOVABLE_DEVICE flag should be set
    slots.removable = false
    ```

    The `directories.tokendir` value defines the filesystem directory for storing PKCS#11 objects. The default value of `/var/lib/softhsm/tokens/` is okay - it will also have been created by the package, and be readable and writable by the `softhsm` group.

The library should now be installed.


## Base slot and `config.toml`

Create a new token and base slot with the following commands:

```sh
# A friendly name for the new token
TOKEN='Key pairs'
# The PKCS#11 user PIN for the new token
PIN='1234'
# The PKCS#11 SO PIN for the new token
SO_PIN="so$PIN"


# This is the `directories.tokendir` in `softhsm2.conf`
rm -rf /var/lib/softhsm/tokens/* &&
softhsm2-util \
    --init-token --free \
    --label "$TOKEN" \
    --so-pin "$SO_PIN" --pin "$PIN"

echo "PKCS#11 base slot URI is pkcs11:token=${TOKEN}?pin-value=${PIN}"
```

In the `/etc/aziot/config.toml`, set the `[aziot_keys]` section as follows:

```toml
[aziot_keys]
pkcs11_lib_path = "<path of the libsofthsm2.so file>"
pkcs11_base_slot = "<the base slot URI printed by the last command above>"
```

For example:

```toml
[aziot_keys]
pkcs11_lib_path = "/usr/lib/arm-linux-gnueabihf/softhsm/libsofthsm2.so"
pkcs11_base_slot = "pkcs11:token=Key pairs?pin-value=1234"
```
