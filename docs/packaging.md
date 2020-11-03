# Packaging

The Identity Service (IS), Keys Service (KS) and Certificates Service (CS) have been explicitly designed to not be Azure IoT Edge-specific; they can be used on non-Edge Azure IoT devices also. To this end, we want to cleanly separate these components from existing association with IoT Edge in the form of hosting it in a separate source repository and shipping it as a separate package. Furthermore, the existing IoT Edge daemon will be renamed (`iotedged` -> `aziot-edged`) and modified to depend on these new components for provisioning the device, managing module identities, and managing cryptographic keys and certificates. `aziot-edged`'s only responsibility will be to act as a Module Runtime (MR) for containerized Edge modules.

Because of these large-scale changes, we plan to make the current `iotedge` Linux package into a long-term servicing (LTS) release. The new components (IS/KS/CS), along with the refactoring for an `aziot-edged` with smaller responsibilities, will be shipped in two new lines of packages:

- `aziot-identity-service`: This package contains the IS, KS and CS components.

- `aziot-edge`: This package contains the MR component needed to deploy dockerized Edge modules. It will have a dependency on the `aziot-identity-service` package, and on the Moby runtime package.

A detailed comparison of the contents of the packages is below.


<table>
<thead>
<th>Item</th>
<th><code>iotedge</code> + <code>libiothsm-std</code></th>
<th><code>aziot-identity-service</code></th>
<th><code>aziot-edge</code></th>
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
    └── config.yaml
```

Note that the configuration is still in YAML format, but reduced in scope.
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


## Installation procedure for non-IoT Edge (`aziot-identity-service` only)

The IS+KS+CS components can still be installed as a standalone package on devices where IoT Edge will **not** be used. They enable an application to provision a device, manage module identities, and manage cryptographic keys and certificates.

```sh
apt install aziot-identity-service

aziot init
```

Similar to IoT Edge's installation procedure, run `aziot init` after installng the package to interactively set up the configuration with minimal information like the device provisioning method.


## Installation procedure for IoT Edge (`aziot-edge`)

```sh
apt install aziot-edge

iotedge init
```

After installing the `aziot-edge` package, run `iotedge init` to interactively set up the configuration. It performs the initialization for both the IS+KS+CS components installed by the `aziot-identity-service` package and the MR component installed by the `aziot-edge` package.


## Updating from `iotedge` to `aziot-edge`

```sh
apt remove iotedge libiothsm-std

apt install aziot-edge

iotedge init
```

The user must remove the existing `iotedge` and `libiothsm-std` packages before installing the `aziot-edge` package (or even the `aziot-identity-service` package). We do not want a situation where the services from both packages are running at the same time. They would step over each other trying to provision the device and manage Docker modules. We enforce mutual exclusivity between the packages by having them conflict with each other so that the distribution's package manager does not allow them both to be installed at the same time.

The `iotedge init` automatically detects when the configuration of the old IoT Edge installation is available and prompts whether to create the new configuration based on the old. Agreeing to import the old configuation does not remove it.

### Initialization Options

The `--force` option can be used to force the initialization sequence to select new configuration values. This writes a new configuration file(s).

```sh
iotedge init --force
```

A non-interactive initialization that attempts to import the old configuration from `iotedge` can be done using the `--import` option.

```sh
iotedge init --import
```

### Automating Upgrades of `iotedge` to `aziot-edge`

We expect that users will manually run the tool when updating the install on the device. Of course, if it has been tested on M devices and the user is confident that it will succeed on the remaining N devices, they can use some custom deployment tooling to automatically perform the update at scale across all their devices.
The process of importing the configuration is intentionally designed to be run manually, rather than being done automatically by the new services. It is potentially fallible and could offline the device.

### Downgrading

The old configuration from `iotedge` is not removed from its location by any of the above actions; therefore, downgrading from the new package to the old one simply involves uninstalling the `aziot-edge` and `aziot-identity-service` packages, then reinstalling the `iotedge` package.

```sh
sudo apt remove aziot-edge aziot-identity-service

sudo apt install iotedge
```

### Technical Details on Migrating Configuration

The precise details are still being worked out. A high-level view is:

- Device provisioning method is parsed from `config.yaml` and translated into the provisioning information in `identityd/config.toml`, `keyd/config.toml` and `certd/config.toml`. For example, in case of manual-symmetric-key provisioning, the SAS key will be imported as a preloaded key in `keyd/config.toml`, and `identityd/config.toml` will be updated to use manual provisioning with a reference to the key ID.

  Some provisioning methods are not yet supported, like DPS-TPM provisioning. The migration will fail in this case.

- User-provided certificates like device ID, device CA and trust bundle, and their corresponding private key files, will be added as preloaded keys and certs in `keyd/config.toml` and `certd/config.toml`. The files themselves will not be moved, because they are managed by the user rather than belonging in our services' directories.

  This assumes that Microsoft's implementation of `libiothsm-std` is being used where the certs and keys are stored as files on disk. This is a reasonable assumption since there are no external Edge customers that have written their own `libiothsm-std` implementations which store keys and certs differently.

- The master identity key and master encryption key are two symmetric keys used internally by `iotedged`. These are created under the `/var/lib/iotedge` homedir and will be moved to the `/var/lib/aziot/keyd/` homedir, and the `keyd/config.toml` updated to preload them.

- Certs like workload CA and module server certs that are created dynamically by `iotedged`, and can be regenerated trivially without any problems, will not be copied or imported into the new services.

## Open Issues

It is not yet certain whether Edge Agent, Edge Hub and other modules will be able to decrypt any data when running against the new services that they previously encrypted using the workload API with the old service.
