# `cryptoauthlib`

Microchip hardware like the ATECC608A is used via a C library called [`cryptoauthlib`.](https://github.com/MicrochipTech/cryptoauthlib) This library can also be compiled with PKCS#11 support so that the device can be accessed via PKCS#11.

This document explains how to compile `cryptoauthlib` [v3.2.1](https://github.com/MicrochipTech/cryptoauthlib/releases/tag/v3.2.1) (the latest as of 2020-07-19) and configure it. It assumes the hardware is attached via I2C. This is the case if you connected it to a Raspberry Pi via a MikroElektronika Click Shield, for example.

See also [upstream's guide,](https://github.com/MicrochipTech/cryptoauthlib/wiki/PKCS11-Linux-Setup#build-and-install-cryptoauthlib-with-pkcs11-support) though as of 2020-07-19 it's slightly outdated since PKCS#11 support is now in master, and needs to be enabled in the cmake file first.

1. Install build dependencies.

    ```sh
    sudo apt install -y cmake udev-dev libgcrypt-dev
    ```

1. Clone the repository.

    ```sh
    git clone https://github.com/MicrochipTech/cryptoauthlib
    git checkout v3.2.1
    cd cryptoauthlib
    ```

1. Build.

    ```sh
    mkdir build
    cd build
    # ATCA_PKCS11 enables PKCS#11 support
    # ATCA_HAL_I2C enables using the hardware via the I2C bus
    cmake -DATCA_PKCS11:STRING=ON -DATCA_HAL_I2C=ON ..
    make "-j$(nproc)"
    ```

1. Install

    ```sh
    sudo make install
    ```

    The library will now be installed. It will also have created `/etc/cryptoauthlib/cryptoauthlib.conf` with the content:

    ```
    # Cryptoauthlib Configuration File

    filestore = /var/lib/cryptoauthlib
    ```

    The `filestore` value defines the filesystem directory for storing PKCS#11 metadata. The default value of `/var/lib/cryptoauthlib` is okay - it will also have been created by `make install`, and be readable and writable by all users.

1. Copy `/var/lib/cryptoauthlib/slot.conf.tmpl` to `/var/lib/cryptoauthlib/0.conf`:

    ```sh
    cp /var/lib/cryptoauthlib/slot.conf.tmpl /var/lib/cryptoauthlib/0.conf
    ```

    ... and edit it as below. This file defines the PKCS#11 slot.

    ```diff
     # Reserved Configuration for a device
     # The objects in this file will be created and marked as undeletable
     # These are processed in order. Configuration parameters must be comma
     # delimited and may not contain spaces

     # Set a label for this slot (optional) - will default to <slot>ABC so
     # 0.conf will have a default label 00ABC
     #label = MCHP

     # Configure the device interface for an enabled HAL
     # hid,i2c,<address>
     # i2c,<address>,<bus>
     # spi,<select_line>,<baud>
    -interface = hid,i2c,0x6c
    +interface = i2c,0x6A,1

     # Configure the device type - base part number (optional)
    -device = ATECC608A-TFLXTLS
    +#device = ATECC608A-TFLXTLS

     #Configure open slots for additional pkcs11 objects (optional)
     #freeslots = 1,2,3
    +freeslots = 2,3,4,5

     # Manually configure keys into device locations (slots/handles)

     # Slot 0 is the primary private key
    -#object = private,device,0
    +object = private,device,0

     # Slot 15 is a public key
     #object = public,root,15
    ```

    The `0` in the filename `0.conf` refers to the PKCS#11 slot number. Thus the PKCS#11 URI for this slot is `pkcs11:slot-id=0`. However the comments inside this file that talk about slots for individual objects are referring to HSM slots, ie the locations where keys are stored, not PKCS#11 slots. For each object dynamically generated in the PKCS#11 slot, the library will create a `<slot number>.<actual device slot number>.conf` file to store PKCS#11 metadata.

    The `interface` value defines the hardware address. For I2C addresses, the value is made up of three parts separated by commas.

    1. The first component is `i2c` to define the kind of address.

    1. The second component is the slave address. This value is calculated by taking the address reported by `i2cdetect -y 1` and multiplying by 2. Eg if `i2cdetect` reports 35, the address is `echo "0x$(bc <<< 'obase = 16; ibase = 16; 35 * 2')"` == `0x6A`. This is because `i2cdetect` reports the address in the lower 7 bits, and cryptoauthlib expects it in the upper 7 bits.

    1. The third component is the bus number. This can be determined by checking the name of the `/dev/i2c-*` file. Eg `/dev/i2c-1` means the bus number is `1`. `i2cdetect -l` will also print the name of the bus.

    The default template conf file has slot `1` listed in the `freeslots` value. You may need to remove `1` from this value if generating key pairs in that slot always fails. (I traced it to the device responding to the `genkey` command packet with `ATCA_COMM_FAIL`, but did not investigate further.)

    Note that each key pair uses only one slot total on the device, not one slot for private key and one slot for public key.

The library should now be configured completely.


## Miscellaneous

1. When using the ATECC608A with a MikroElektronika Click Shield on a Raspberry Pi, ensure `/boot/config.txt` contains

    ```
    dtdebug=on
    dtparam=i2c_arm=on
    ```

    (You probably want to connect it to the left slot of the click shield so that the right slot is available for the Infineon SLB9670 TPM.)

1. `pkcs11-tool --module /usr/lib/libcryptoauth.so -IOT` for some reason does not see any attributes of the PKCS#11 objects. Use `p11tool --list-all 'pkcs11:model=ATECC608A'` instead.

1. As mentioned above, the library creates files named like `<slot number>.<actual device slot number>.conf` to store PKCS#11 metadata about dynamically-generated keys. Therefore, deleting these object files will make the PKCS#11 library "forget" about those objects, even if the actual hardware slot is occupied, so it's a handy way to "reset" the device for tests. Note that the library maintains the state of which slots are used in memory as well, so deleting the files only has an effect if the process using the library (`pkcs11-test`, `aziot-keyd`, etc) is restarted.
