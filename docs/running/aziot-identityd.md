
# Configuring and running `aziot-identityd`

Basic Identity Service configuration file consists of following mandatory settings:

```toml
    hostname = "devicehostname"
    homedir = "/var/lib/aziot/identityd"

    [connect]

    [listen]

    [provisioning]
    
    [[principal]]
```
- `hostname` is the device's network hostname. This setting is used for nested topology configuration. 

- `homedir` is the folder path that stores Identity Service persistent state. This setting is used for storing Identity Service state. 

- `[connect]` contains the Unix domain socket address where Identity Service clients can access its APIs. This setting is reserved for future use for UDS configuration. 

- `[listen]` contains the listening address for Identity Service clients. This setting is reserved for future use for systemd / UDS configuration.

- `[provisioning]` contains the device provisioning endpoint and credential settings. The Identity Service supports DPS and manual provisioning modes.

    Depending on the provisioning `source` type, one of `[provisioning.attestation]` (for `dps` source) or `[provisioning.authentication]` (for `manual` source) subsections must be provided.

- `[[principal]]` contains a table of host-process client information. The Identity Service uses the information to provision cloud identities for host processes (using the `name` property), authenticate API clients (using the `uid` property) and manage API access to identity resources (using the `idtype` property).

## Configuring device provisioning

The `[provisioning.attestation]` section is configured in one of following ways, depending on the provisioning method selected by the device operator:

1. Automated provisioning of IoT Hub device identity using DPS with X.509 attestation - 

```toml
	[provisioning]
	"source" = "dps"
	"scope_id" = "<ADD DPS SCOPE ID HERE>"

    [provisioning.attestation]
	"method" = "x509"
    "registration_id" = "<ADD DPS REGISTRATION ID HERE>" # Optional for X.509 attestation
	"identity_cert" = "device-id-cert-handle" # Pre-loaded Certificate service handle
	"identity_pk" = "device-id-key-handle" # Pre-loaded Key service handle
```

2. Automated provisioning of IoT Hub device identity using DPS with symmetric key attestation - 

```toml
    [provisioning]
	"source" = "dps"
	"scope_id" = "<ADD DPS SCOPE ID HERE>"

    [provisioning.attestation]
    "method" = "symmetric_key"
    "registration_id" = "<ADD DPS REGISTRATION ID HERE>" # Required for symmetric key attestation
    "symmetric_key" = "device-id-symkey-handle" # Pre-loaded Key service handle
```

- The `provisioning.attestation.identity_pk` and `provisioning.attestation.symmetric_key` values are preloaded key IDs defined in the Key Service.

- The `provisioning.attestation.identity_cert` value is a preloaded cert ID in the Certificate Service.


3. Manual provisioning of IoT Hub device identity using X.509 - 

```toml
    [provisioning]
    source = "manual"
    iothub_hostname = "<ADD IOT HUB HOSTNAME HERE>"
    device_id = "iothubdeviceid"

    [provisioning.authentication]
    method = "x509"
    identity_cert = "device-id" # Pre-loaded Certificate service handle
    identity_pk = "device-id" # Pre-loaded Key service handle
```


4. Manual provisioning of IoT Hub device identity using shared private key - 

```toml
    [provisioning]
    source = "manual"
    iothub_hostname = "<ADD IOT HUB HOSTNAME HERE>"
    device_id = "<ADD IOT HUB DEVICE ID HERE>"
    
    [provisioning.authentication]
    method = "sas"
    device_id_pk = "device-id" # Pre-loaded Key service handle
```

- The `provisioning.authentication.device_id_pk` and `provisioning.authentication.symmetric_key` values are preloaded key IDs defined in the Key Service.

- The `provisioning.authentication.device_id_cert` value is a preloaded cert ID in the Certificate Service.

## Configuring host process clients

> Dev Note: Currently, host process clients connect over TCP port 8091. This section is applicable after final packaging and Unix Domain Socket support is enabled in IS.

The table of principal accounts in Identity Service configuration represents each host process client of the Identity Service (known as `principal`s). The `principal` table entries are used to map access to one or more identity resources to a Unix user`uid`. Each `principal` table entry is configured using one of the following methods:

1. Host daemon process that actively manages cloud identities (e.g. IoT Edge)

```toml
    [[principal]]
    uid = 1001
    name = "hostdaemon1"
```

2. Host process that operations using a cloud module identity (e.g. device agents that can connect using IoT Hub module identities)

```toml
    [[principal]]
    uid = 1002
    name = "hostprocess2" # Module name created in IoT Hub by Identity Service
    idtype = "module"
```

3. Host process that operates using a provisioned cloud device identity (e.g. device agents that can connect using IoT Hub device identities)

```toml
    [[principal]]
    uid = 1003
    name = "hostprocess1"
    idtype = "device"

```

- `uid` is the Unix userid of the host process client. The host process transmits its `uid` during each connect operation (over Unix Domain Sockets) to the Identity Service. This value must be unique per principal. 

- `name` is the host process caller name. If the caller is `idtype = module`, then the module identity is provisioned by Identity Service in Azure IoT Hub with that `name`. 

- `idtype` (optional) is the identity type returned to that host process associated with the IoT Hub identity type being returned to that host process - it is either `device` identity or `module` identity. If `idtype` is not specified, the caller will be authorized to access all cloud identity resources (except those created by Identity Service for host processes). If the `idtype` is `module`, the `name` will be used by the Identity Service to generate new cloud identities, if not created already. `idtype = device` is only used in special cases, when the host process needs to retrieve the provisioned device identity, instead of module identity.

## Running `aziot-identityd`

Run the following command to launch the Identity Service, passing the `config.toml` file path as an argument:

```sh
cargo run -p aziot-identityd -- -c /path/to/default.toml
```

