# `tpm2-pkcs11`

All TPM 2.0 TPMs can be accessed via PKCS#11 using the [`tpm2-pkcs11` library.](https://github.com/tpm2-software/tpm2-pkcs11)

`tpm2-pkcs11` depends on a few other `tpm2-*` libraries, some of which may exist in distro packages but may be outdated. Therefore it is recommended to compile all the libraries yourself. This document contains a script to compile the following libraries:

- `tpm2-abrmd` v2.3.2
- `tpm2-pkcs11` v1.3.0
- `tpm2-tools` v4.2.1
- `tpm2-tss` v2.4.1

... which are the latest as of 2020-07-19.

Note that the version numbers of these tools don't follow any common numbering, so you need to be careful to use versions that are compatible with each other. See <https://tpm2-software.github.io/versions/#tpm2-tools> for a list of compatible versions.


```sh
#!/bin/bash

set -euo pipefail


# Install build dependencies

sudo apt install \
    git \
    autoconf automake doxygen libtool \
    libcurl4-openssl-dev libdbus-1-dev libgcrypt-dev \
    libglib2.0-dev libjson-c-dev libsqlite3-dev libssl-dev \
    python3-cryptography python3-yaml uuid-dev libyaml-dev


# Create base source directory

mkdir -p ~/src


# Define the version numbers
#
# Refs:
# - https://tpm2-software.github.io/versions/#tpm2-tools
# - https://github.com/tpm2-software/tpm2-abrmd/releases
# - https://github.com/tpm2-software/tpm2-pkcs11/releases
# - https://github.com/tpm2-software/tpm2-tools/releases
# - https://github.com/tpm2-software/tpm2-tss/releases

declare -A checkouts

checkouts['tpm2-abrmd']='2.3.2'
checkouts['tpm2-pkcs11']='1.3.0'
checkouts['tpm2-tools']='4.2.1'
checkouts['tpm2-tss']='2.4.1'


# Download `autoconf-2019.01.06` and extract it

[ -f ~/src/autoconf-archive-2019.01.06.tar.gz ] || curl -Lo ~/src/autoconf-archive-2019.01.06.tar.gz 'https://github.com/autoconf-archive/autoconf-archive/archive/v2019.01.06.tar.gz'
[ -d ~/src/autoconf-archive-2019.01.06 ] || (cd ~/src/ && tar xf ~/src/autoconf-archive-2019.01.06.tar.gz)


# Clone and bootstrap the repositories

for d in "${!checkouts[@]}"; do
    (
        set -euo pipefail

        [ -d ~/src/"$d" ] || git clone "https://github.com/tpm2-software/$d" ~/src/"$d"
        cd ~/src/"$d"

        git fetch --all --prune
        git clean -xffd
        git reset --hard
        git checkout "${checkouts["$d"]}"

        cp -R ~/src/autoconf-archive-2019.01.06/m4 .

        ./bootstrap -I m4
    ) & :
done

wait $(jobs -pr)


# Build `tpm2-tss`

(
    set -euo pipefail

    cd ~/src/tpm2-tss

    ./configure --with-udevrulesdir=/etc/udev/rules.d --with-udevrulesprefix=70-
    make "-j$(nproc)"
    sudo make install
    id -u tss || sudo useradd --system --user-group tss
    sudo udevadm control --reload-rules
    sudo udevadm trigger
    sudo ldconfig
)


# Build `tpm2-abrmd`

(
    set -euo pipefail

    cd ~/src/tpm2-abrmd

    ./configure --with-dbuspolicydir=/etc/dbus-1/system.d --with-systemdsystemunitdir=/lib/systemd/system --with-systemdpresetdir=/lib/systemd/system-preset --datarootdir=/usr/share
    make "-j$(nproc)"
    sudo make install
    sudo ldconfig
    sudo pkill -HUP dbus-daemon
    sudo systemctl daemon-reload
    sudo systemctl enable tpm2-abrmd.service
    sudo systemctl restart tpm2-abrmd.service

    # Verify that the service started and registered itself with dbus
    dbus-send --system '--dest=org.freedesktop.DBus' '--type=method_call' --print-reply '/org/freedesktop/DBus' 'org.freedesktop.DBus.ListNames' | grep -q 'com.intel.tss2.Tabrmd' || :
)


# Build `tpm2-tools`

(
    set -euo pipefail

    cd ~/src/tpm2-tools

    ./configure
    make "-j$(nproc)"
    sudo make install
)


# Build tpm2-pkcs11

(
    set -euo pipefail

    cd ~/src/tpm2-pkcs11

    # The `tpm2-pkcs11` library uses a filesystem directory to store wrapped keys.
    # Ensure this directory is readable and writable by the user you'll be running `pkcs11-test` / `aziot-keyd` as, not just root.
    sudo mkdir -p /opt/tpm2-pkcs11
    sudo chown "$(id -u):$(id -g)" /opt/tpm2-pkcs11
    sudo chmod 0700 /opt/tpm2-pkcs11

    ./configure --enable-esapi-session-manage-flags --with-storedir=/opt/tpm2-pkcs11
    make "-j$(nproc)"
    sudo make install
)
```

The library should now be configured completely.


## Miscellaneous

1. When using the Infineon SLB9670 with a MikroElektronika Click Shield on a Raspberry Pi, connect the TPM to the right slot of the click shield and ensure `/boot/config.txt` contains:

    ```
    dtdebug=on
    gpio=12=op,dh
    dtoverlay=tpm-slb9670
    ```

    If you did it correctly, the kernel should recognize the TPM and create `/dev/tpm0`

    Do **not** connect the TPM to the left slot of the click shield. The `tpm-slb9670` overlay uses the chip-enable pin that ends up being mapped to the right slot.
