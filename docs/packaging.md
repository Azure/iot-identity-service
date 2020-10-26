# Packaging

The Identity Service (IS), Keys Service (KS) and Certificates Service (CS) have been explicitly designed to not be Azure IoT Edge-specific; they can be used on non-Edge Azure IoT devices also. To this end, we want to cleanly separate these components from existing association with IoT Edge in the form of hosting it in a separate source repository and shipping it as a separate package. Furthermore, the existing IoT Edge daemon will be modified to depend on these components for provisioning the device, managing module identities, and managing cryptographic keys and certificates, and thus its only responsibility will be to act as a Module Runtime (MR).

Because of these large-scale changes, we plan to make the current `iotedge` Linux package into an LTS line. The new components, including the new `iotedged` with smaller responsibilities, will be shipped in two new lines of packages:

- `aziot-identity-service`: This package contains the IS, KS and CS components.

- `iotedge-aziot`: This package contains the MR component needed to deploy dockerized Edge modules. It will have a dependency on the `aziot-identity-service` package, and on the Moby runtime package.

A detailed comparison of the contents of the packages is below.


<table>
<thead>
<th>Item</th>
<th><code>iotedge</code> + <code>libiothsm-std</code></th>
<th><code>aziot-identity-service</code></th>
<th><code>iotedge-aziot</code></th>
</thead>
<tbody>
<tr>
<td>Source repository</td>
<td><code>https://github.com/Azure/iotedge</code></td>
<td><code>https://github.com/Azure/iot-identity-service</code></td>
<td><code>https://github.com/Azure/iotedge</code></td>
</tr>
<tr>
<td>Binaries and libraries</td>
<td>

```
/usr/
├── bin/
│   ├── iotedge
│   └── iotedged
└── lib/
    └── libiothsm.so
```

The `iotedge` CLI tool is used to interact with the `iotedged` service.
</td>
<td>

```
/usr/
├── bin/
│   └── aziot
├── lib/
│   └── libaziot_keys.so
└── libexec/
    └── aziot/
        ├── aziot-certd
        ├── aziot-identityd
        └── aziot-keyd
```

The `aziot` CLI tool is used to interact with the three `aziot-*` services.

(The `aziot-*` binaries are installed under the "libexec" directory, meant for executables that are not intended to be directly invoked by a user. Most distributions map this directory to `/usr/lib/`, which is why the tree above shows them under `/usrlib/aziot/`)
</td>
<td>

```
/usr/
├── bin/
│   └── iotedge
└── libexec/
    └── aziot/
        └── aziot-edged
```

The `iotedge` CLI tool is used to interact with the `aziot-edged` service.
</td>
</tr>
<tr>
<td>Config files</td>
<td>

```
/etc/
└── iotedge/
    └── config.yaml
```
</td>
<td>

```
/etc/aziot/
├── certd/
│   └── config.toml
├── identityd/
│   └── config.toml
└── keyd/
    └── config.toml
```

Note that the configuration is now in TOML format.
</td>
<td>

```
/etc/aziot/
└── edged/
    └── config.toml
```

Note that the configuration is now in TOML format.
</td>
</tr>
<tr>
<td>API socket files</td>
<td>

```
/var/run/
└── iotedge/
    ├── mgmt.sock
    └── workload.sock
```
</td>
<td>

```
/run/aziot/
├── certd.sock
├── identityd.sock
└── keyd.sock
```
</td>
<td>

```
/run/aziot/
└── edged/
    ├── mgmt.sock
    └── workload.sock
```
</td>
</tr>
<tr>
<td>Systemd service and socket files</td>
<td>

```
/usr/lib/systemd/system/
├── iotedge.service
├── iotedge.socket
└── iotedge.mgmt.socket
```
</td>
<td>

```
/usr/lib/systemd/system/
├── aziot-certd.service
├── aziot-certd.socket
├── aziot-identityd.service
├── aziot-identityd.socket
├── aziot-keyd.service
└── aziot-keyd.socket
```
</td>
<td>

```
/usr/lib/systemd/system/
├── aziot-edged.service
├── aziot-edged.mgmt.socket
└── aziot-edged.workload.socket
```
</td>
</tr>
<tr>
<td>Unix groups (used to ACL the service sockets)</td>
<td>

`iotedge` - The `iotedge.mgmt.sock` socket

</td>
<td>

- `aziotcs` - The CS socket
- `aziotid` - The IS socket
- `aziotks` - The KS socket
</td>
<td>

`iotedge` - The MR management socket
</td>
</tr>
<tr>
<td>Home directories</td>
<td>

```
/var/lib/iotedge/
└── hsm/
    ├── certs/
    ├── cert_keys/
    └── enc_keys/
```
</td>
<td>

```
/var/lib/aziot/
├── certd/
│   └── certs/
├── identityd/
└── keyd/
    └── keys/
```
</td>
<td>

```
/var/lib/aziot/
└── edged/
```
</td>
</tr>
<tr>
<td>Package dependencies</td>
<td>

- `moby-engine`
- `openssl`
</td>
<td>

- `openssl`
</td>
<td>

- `aziot-identity-service`
- `moby-engine`
- `openssl`
</td>
</tr>
</tbody>
</table>


## Installation procedure (`aziot-identity-service` only)

```sh
apt install aziot-identity-service

aziot init
```

The user installs the package, then runs `aziot init` to set up the configuration with minimal information like the device provisioning method.


## Installation procedure (`iotedge-aziot`)

```sh
apt install iotedge-aziot

iotedge init
```

The user installs the package, then runs `iotedge init` to set up the configuration of the IS+KS+CS+MR components.


## Migration procedure for existing users of `iotedge` to `iotedge-aziot`

```sh
apt remove iotedge libiothsm-std

apt install iotedge-aziot

iotedge migrate
```

The user removes the existing `iotedge` and `libiothsm-std` packages, installs the new package, then runs `iotedge migrate` to migrate the configuration of the old IoT Edge installation to the new one. It is important that the user uninstalls the `iotedge` package before installing the `iotedge-aziot` (or even the `aziot-identity-service` package; we do not want a situation where the services from both packages are running at the same time because they will step over each other trying to provision the device and trying to manage Docker modules. We will enforce this in the packages by having them conflict with each other, so that the distribution's package manager will not allow them both to be installed at the same time either.

The precise details of the migration are still being worked out. A high-level view is:

- Device provisioning method is parsed from `config.yaml` and translated into the provisioning information in `identityd/config.toml`, `keyd/config.toml` and `certd/config.toml`. For example, in case of manual-symmetric-key provisioning, the SAS key will be imported as a preloaded key in `keyd/config.toml`, and `identityd/config.toml` will be updated to use manual provisioning with a reference to the key ID.

  Some provisioning methods are not supported, like DPS-TPM provisioning, so the migration will fail in this case.

- User-provided certificates like device ID, device CA and trust bundle, and their corresponding private key files, will be added as preloaded keys and certs in `keyd/config.toml` and `certd/config.toml`. The files themselves will not be moved, because they are managed by the user rather than belonging in our services' directories.

  This assumes that Microsoft's implementation of `libiothsm-std` is being used where the certs and keys are stored as files on disk. This is a reasonable assumption since there are no external Edge customers that have written their own `libiothsm-std` implementations which store keys and certs differently.

- The master identity key and master encryption key are two symmetric keys used internally by `iotedged`. These are created under the `/var/lib/iotedge` homedir and will be moved to the `/var/lib/aziot/keyd/` homedir, and the `keyd/config.toml` updated to preload them.

- Certs like workload CA and module server certs that are created dynamically by `iotedged`, and can be regenerated trivially without any problems, will not be copied or imported into the new services.

The process of migration is intentionally designed to be run manually by the user, rather than being done automatically by the new services, because it is both fallible and could potentially offline the device. Therefore we expect that users will manually run the tool to update the device. Of course, if the user has tested on M devices and is confident that it will succeed on their remaining N devices, they can use some custom deployment tooling to automatically perform the migration at scale across all their devices.

For the files that are copied to new locations, it is important to note that they are not deleted from their previous locations. Therefore the user can still downgrade from the new package to the old one by uninstalling the `iotedge-aziot` and `aziot-identity-service` packages, then reinstalling the `iotedge` package.

It is not yet certain whether Edge Agent, Edge Hub and other modules will be able to decrypt any data when running against the new services that they previously encrypted using the workload API with the old service.
