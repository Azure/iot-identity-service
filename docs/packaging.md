# Packaging

The Identity Service (IS), Keys Service (KS), Certificates Service (CS) and TPM Service (TPMS) are stand-alone components that can be used on Linux-based Azure IoT devices to ease the process of provisioning the device with Azure, to allow modules on the device to securely and cooperatively connect to IoT Hub using module identities, and to provide common cryptographic services to modules like HSM-backed keys and CA-issued certificates.

On Azure IoT Edge devices, these services form the backbone of the Azure IoT Edge service - the Azure IoT Edge service relies on the Identity Service to provision the Edge device identity and Edge module identities in Azure, to provide the CA certificate used for module server certificates like Edge Hub's, and so on. For more in-depth discussion of the IoT Edge package, refer to its documentation on ["Packaging".](https://github.com/Azure/iotedge/blob/master/doc/packaging.md)

These components ship in the `aziot-identity-service` package. This document describes the contents of this package and how to install and configure it.


## Binaries and libraries

```
/usr/
├── bin/
│   └── aziotctl
├── lib/
│   ├── libaziot_keys.so
│   └── engines-1.1/
│   │   └── aziot_keys.so
└── libexec/
    └── aziot/
        ├── aziotd
        ├── aziot-certd -> aziotd
        ├── aziot-identityd -> aziotd
        ├── aziot-keyd -> aziotd
        └── aziot-tpmd -> aziotd
```

The `aziotctl` CLI tool is used to manage and interact with the services.

The service binaries are installed under the distribution's "libexec" directory, since they're executables that are not intended to be directly invoked by a user and thus do not to be in `PATH`. Furthermore, all the services are compiled into a single binary `/usr/libexec/aziot/aziotd`, and the individual service binaries are just
differently-named symlinks to this `aziotd` binary. This saves space since a lot of code in the services is statically linked and can be shared. The `aziotd` binary looks at its `argv[0]` to determine which service it's being asked to run as.

`/usr/lib/libaziot_keys.so` is a library used by the KS for pluggable cryptographic key storage. It exposes a simple C API and is designed to be replaceable by the user if they need to. However the implementation shipped by default is already quite versatile, since it supports both filesystem keys as well as all HSMs with PKCS#11 libraries, so we don't expect users to need to replace it.

`/usr/lib/engines-1.1/aziot_keys.so` is an OpenSSL engine that can be used for mTLS when the client certificate's private key is backed by the KS. See ["Openssl engine internals"](openssl-engine-internals.md) for details.


## Config files


```
/etc/aziot/
├── config.toml.template
├── certd/
│   ├── config.d/
│   └── config.toml.default
├── identityd/
│   ├── config.d/
│   └── config.toml.default
├── keyd/
│   ├── config.d/
│   └── config.toml.default
└── tpmd/
    ├── config.d/
    └── config.toml.default
```

The services read the following files for their configuration:
- `config.toml` in the service directory. Eg `/etc/aziot/certd/config.toml`
- Any `*.toml` files in the service's `config.d` directory. Eg `/etc/aziot/certd/config.d/50-overrides.toml`

All files found in this way are unioned. The `config.toml` is considered first, then the files in `config.d` in alphabetical order. If the same setting is specified in two config files, the setting in the file considered second overrides the setting in the file considered first.

Every service has a corresponding `config.toml.default` file that indicates the default settings for that service if no config file is provided.

However, we expect the user to primarily configure the services via the "super-config" file. A template of this file is installed at `/etc/aziot/config.toml.template`. The easiest way for the user to configure all services is to copy this template to a new file, say `/etc/aziot/config.toml`, edit it, then "apply" the contents of the file to all the services with `sudo aziotctl config apply`.

This is explained in more detail in the ["Installing and configuring the package"](#installing-and-configuring-the-package) section below.


## Service endpoint socket files

```
/run/aziot/
├── certd.sock
├── identityd.sock
├── keyd.sock
└── tpmd.sock
```


## Systemd service and socket units

```
/usr/lib/systemd/system/
├── aziot-certd.service
├── aziot-certd.socket
├── aziot-identityd.service
├── aziot-identityd.socket
├── aziot-keyd.service
├── aziot-keyd.socket
├── aziot-tpmd.service
└── aziot-tpmd.socket
```

Note that the `.socket` units will start up the corresponding `.service` units automatically if something attempts to connect to the corresponding socket file. For this reason, the default state is to `aziot-certd.service`, `aziot-keyd.service` and `aziot-tpmd.service` stopped, and only enable their `.socket`s to start up automatically on boot. Both `aziot-identityd.service` and `aziot-identityd.socket` should be enabled to start up on boot, however, so that the device always provisions itself.


## Unix users and groups

CS: `aziotcs`

IS: `aziotid`

KS: `aziotks`

TPMS: `aziottpm`

Each service runs as the corresponding user. Each user belongs to a group of the same name, and the service's endpoint socket file is owned by its user and group. Therefore, in order for a process to communicate with a service, the process's user must be added to the service's group to be able to connect to the endpoint socket file.

For example, if you have a module process, the process needs to interact with the IS to get its module identity, with the KS to be able to use its module identity key to create a SAS token or for mTLS, and with the CS in order to use its module identity certificate for mTLS. So you should add the user that your module runs as to the `aziotid`, `aziotks` and `aziotcs` groups.


## Home directories

```
/var/lib/aziot/
├── certd/
│   └── certs/
├── identityd/
├── keyd/
│   └── keys/
└── tpmd/
```

`/var/lib/aziot/certd/certs` stores any certificates imported or generated by CS.

`/var/lib/aziot/keyd/keys` stores any keys imported or generated by KS that could not be stored in an HSM via PKCS#11. (This is the case if the HSM doesn't support that particular kind of key, or if KS was not configured to use PKCS#11 at all.)


## Package dependencies

The binaries and libraries shipped in this package only depend on OpenSSL (v1.0 on CentOS 7, v1.1 on other supported distributions).

If you plan to use a PKCS#11 library with KS to store your cryptographic keys in an HSM or TPM, you will need to install this library and its dependencies in accordance with your HSM manufacturer.


# Installing and configuring the package

As mentioned above, the `aziot-identity-service` package ships with the template of a "super-config", at `/etc/aziot/config.toml/template`. The easiest way for the user to configure all services is to copy this template to a new file, say `/etc/aziot/config.toml`, edit it, then "apply" the contents of the file to all the services with `sudo aziotctl config apply`.

This file is called the "super-config" because it is an amalgamation of all the configurations of the individual services, with some simplifications. Since most use cases would require the user to keep all the service configs in sync with each other, this approach of having a single "super-config" helps make it easier and reduce errors.

For example, if the user wanted to configure their device to use DPS provisioning with X.509 attestation, they would have to configure the certificate's private key as a preloaded key file URI in the KS config, the certificate as a preloaded cert file URI in the CS config, and the provisioning method in IS to use those private key and certificate via their IDs. With the super-config, they are instead able to configure provisioning to use those key and cert file URIs directly. `aziotctl config apply` does the job of converting the "super-config" into the individual services' configs, which includes synthesizing IDs for the key and cert and hooking them all up correctly.

Therefore, the easiest way to install and configure the package is:

```sh
# Install the package
sudo apt install aziot-identity-service

# Copy the config template into a new empty config.
sudo cp /etc/aziot/config.toml.template /etc/aziot/config.toml

# Edit the new empty config and fill in your provisioning information,
# plus anything else you want to customize. See comments in the file for details.
sudo $EDITOR /etc/aziot/config.toml

# Apply the new config to all the services and restart them as necessary.
sudo aziotctl config apply
```
