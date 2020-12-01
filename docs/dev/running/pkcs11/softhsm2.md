# `softhsm2`

`softhsm2` is a PKCS#11 library that emulates an HSM entirely in software. It implements key operations using `openssl`.

While it is useful to use `softhsm2` when you don't have any hardware, it is worth noting that it generally supports more PKCS#11 features than what PKCS#11 libraries of most hardware support.

1. Install `softhsm2`

    ```sh
    sudo apt install -y softhsm2
    ```

1. The `softhsm2` configuration and filesystem directory is ACLed to the `softhsm` group. Add the user you'll be running `aziot-keyd` as to this group.

    ```sh
    sudo usermod -aG softhsm "$(id -un)"
    ```

    To have the new membership take effect, start a new login shell, or update the existing one with `newgrp softhsm`

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

The library should now be configured completely.
