# Identity Service

## API

### Get primary cloud identity for authenticated workload

`GET /identities/identity?api-version=2020-09-01`

The shape of the response will depend on the principal used to authenticate with the Identity Service. The association between an authorized principal and the identity type to return is based on the `idtype` in the identity service's [configuration](identity-service.md#module-provisioning--re-provisioning).

The returned `auth.keyHandle` value is meant to be used with the [Keys Service](keys-service.md), depending on the `auth.type` value:

- If `auth.type` is `"sas"`, `keyHandle` is a handle to the identity's primary shared access key, which can be used to generate a security token (for IoT Hub authentication) using the Keys Service's [sign](keys-service.md#sign) operation.

- If `auth.type` is `"x509"`, `keyHandle` is a handle to the identity X.509 certificate's private key. The `auth.certId` contains the certificate ID of the identity X.509 certificate, which can be retrieved used using the [Certificates Service.](certificates-service.md) Together this private key and certificate should be used for IoT Hub authentication via client certificate.

  For convenience, the Identity Service package ships with an openssl engine that can load the handles of private keys. If the caller of this API uses openssl for TLS, it can use this engine. More details can be found on the [OpenSSL engine internals](../../docs-dev/openssl-engine-internals.md) page.

#### Response for principals associated to device identities (SAS case)

```json
{
  "type": "aziot",
  "spec":
  {
    "hubName": "myhub.net",
    "gatewayHost": "parentdevice",
    "deviceId": "device01",
    "auth": {
        "type": "sas",
        "keyHandle": "string"
    }
  }
}
```

#### Response for principals associated to device identities (X.509 case)

```json
{
  "type": "aziot",
  "spec" :
  {
    "hubName": "myhub.net",
    "gatewayHost": "parentdevice",
    "deviceId": "device01",
    "auth": {
        "type": "x509",
        "keyHandle": "string",
        "certId": "string"
    }
  }
}
```

#### Response for principals associated to module identities (SAS case)
```json
{
  "type": "aziot",
  "spec":
  {
    "hubName": "myhub.net",
    "gatewayHost": "parentdevice",
    "deviceId": "device01",
    "moduleId": "module01",
    "genId": "12345",
    "auth": {
        "type": "sas",
        "keyHandle": "string"
   }
  }
}
```

#### Response for principals associated to module identities (X.509 case)
```json
{
  "type": "aziot",
  "spec":
  {
    "hubName": "myhub.net",
    "gatewayHost": "parentdevice",
    "deviceId": "device01",
    "moduleId": "module01",
    "genId": "12345",
    "auth": {
        "type": "x509",
        "keyHandle": "string",
        "certId": "string"
    }
  }
}
```

---

### Get IoT device provisioning result

`POST /identities/device?api-version=2020-09-01`

#### Request
```json
{
  "type": "aziot"
}
```

#### Response (SAS case)
```json
{
  "type": "aziot",
  "spec":
  {
    "hubName": "myhub.net",
    "gatewayHost": "parentdevice",
    "deviceId": "device01",
    "auth": {
        "type": "sas",
        "keyHandle": "string"
    }
  }
}
```

#### Response (X.509 case)

```json
{
  "type": "aziot",
  "spec" :
  {
    "hubName": "myhub.net",
    "gatewayHost": "parentdevice",
    "deviceId": "device01",
    "auth": {
        "type": "x509",
        "keyHandle": "string",
        "certId": "string"
    }
  }
}
```

---

### List IoT Module Identities
`GET /identities/modules?api-version=2020-09-01&type={type}`

The `type` query parameter specifies the identity type to return. Accepted values are:
- `aziot`: Module identity.

#### Response (SAS case)
```json
{
  "identities": [
    {
      "type": "aziot",
      "spec":
      {
        "hubName": "myhub.net",
        "gatewayHost": "parentdevice",
        "deviceId": "device01",
        "moduleId": "module01",
        "genId": "12345",
        "auth": {
            "type": "sas",
            "keyHandle": "string"
        }
      }
    }
  ]
}
```

#### Response (X.509 case)

```json
{
  "identities": [
    {
      "type": "aziot",
      "spec":
      {
        "hubName": "myhub.net",
        "gatewayHost": "parentdevice",
        "deviceId": "device01",
        "moduleId": "module01",
        "genId": "12345",
        "auth": {
            "type": "x509",
            "keyHandle": "string",
            "certId": "string"
        }
      }
    }
  ]
}
```

---

### Create IoT module identity

`POST /identities/modules?api-version=2020-09-01`

#### Request (Module identity)
```json
{
  "type": "aziot",
  "moduleId": "module01"
}
```

#### Request (Local identity)
```json
{
  "type": "local",
  "moduleId": "module01",
  "localIdOpts": {
    "type": "x509",
    "attributes": "server"
  }
}
```

`localIdOpts` is an optional field that can be used to specify configuration of the issued local identity. It contains the following fields:
- `type` - Type of local identity. Currently, only `x509` is supported.
- `attributes` - Attributes of the X.509 local identity certificate. May be either `client` or `server`.

If `localIdOpts` is not specified, the default `{"type": "x509", "attributes": "client"}` will be used.

#### Response (SAS case)

```json
{
  "type": "aziot",
  "spec":
  {
    "hubName": "myhub.net",
    "gatewayHost": "parentdevice",
    "deviceId": "device01",
    "moduleId": "module01",
    "genId": "12345",
    "auth": {
        "type": "sas",
        "keyHandle": "string"
   }
  }
}
```

#### Response (X.509 case)

```json
{
  "type": "aziot",
  "spec":
  {
    "hubName": "myhub.net",
    "gatewayHost": "parentdevice",
    "deviceId": "device01",
    "moduleId": "module01",
    "genId": "12345",
    "auth": {
        "type": "x509",
        "keyHandle": "string",
        "certId": "string"
    }
  }
}
```

#### Response (Local identity)

```json
{
  "type": "local",
  "spec":
  {
    "moduleId": "module01",
    "auth": {
        "privateKey": "private key bytes",
        "certificate": "certificate bytes",
        "expiration": "yyyy-mm-ddThh:mm:ss+00:00"
    }
  }
}
```

---

### Get IoT module identity information

`GET /identities/modules/{module-id}?api-version=2020-09-01&type={type}`

The `type` query parameter specifies the identity type to return. Accepted values are:
- `aziot`: Module identity.
- `local`: Local identity.

#### Response (SAS case)
```json
{
  "type": "aziot",
  "spec":
  {
    "hubName": "myhub.net",
    "gatewayHost": "parentdevice",
    "deviceId": "device01",
    "moduleId": "module01",
    "genId": "12345",
    "auth": {
        "type": "sas",
        "keyHandle": "string"
   }
  }
}
```

#### Response (X.509 case)

```json
{
  "type": "aziot",
  "spec":
  {
    "hubName": "myhub.net",
    "gatewayHost": "parentdevice",
    "deviceId": "device01",
    "moduleId": "module01",
    "genId": "12345",
    "auth": {
        "type": "x509",
        "keyHandle": "string",
        "certId": "string"
    }
  }
}
```

#### Response (Local identity)

```json
{
  "type": "local",
  "spec":
  {
    "moduleId": "module01",
    "auth": {
        "privateKey": "private key bytes",
        "certificate": "certificate bytes",
        "expiration": "yyyy-mm-ddThh:mm:ss+00:00"
    }
  }
}
```

---

### Update IoT module identity

`PUT /identities/modules/{module-id}?api-version=2020-09-01`

#### Request
```json
{
  "type": "aziot",
  "moduleId": "module01"
}
```

#### Response (SAS case)
```json
{
  "type": "aziot",
  "spec":
  {
    "hubName": "myhub.net",
    "gatewayHost": "parentdevice",
    "deviceId": "device01",
    "moduleId": "module01",
    "genId": "12345",
    "auth": {
        "type": "sas",
        "keyHandle": "string"
   }
  }
}
```

#### Response (X.509 case)

```json
{
  "type": "aziot",
  "spec":
  {
    "hubName": "myhub.net",
    "gatewayHost": "parentdevice",
    "deviceId": "device01",
    "moduleId": "module01",
    "genId": "12345",
    "auth": {
        "type": "x509",
        "keyHandle": "string",
        "certId": "string"
    }
  }
}
```

---

### Delete IoT module identity

`DELETE /identities/modules/{module-id}?api-version=2020-09-01&type={type}`

The `type` query parameter specifies the identity type to return. Accepted values are:
- `aziot`: Module identity.

#### Response

```
204 No Content
```

---

### Trigger IoT device reprovisioning flow

`POST /identities/device/reprovision?api-version=2020-09-01`

#### Request

```json
{
  "type": "aziot"
}
```

#### Response

```
204 No Content
```

---

## Notes on IS operations

### Module Provisioning / Re-provisioning

IoT Hub module identities will get generated by Identity service (IS) for containerized and host process workloads. Once the device identity is provisioned by IS, the IS can begin generating module identities associated with that device identity. There are two steps to configure IS to start generating module identities -

1. IS configuration

    ```toml
    [[principal]]
    uid = 1001
    name = "hostdaemon1"

    [[principal]]
    uid = 1002
    name = "hostprocess1"
    idtype = ["device"]

    [[principal]]
    uid = 1003
    name = "hostprocess2"
    idtype = ["module", "local"]
    ```

    The table of principal accounts in IS configuration represents all the host process callers of IS APIs (known as `principal`s) and their corresponding OS userid.

    `uid` is the OS userid that will be included in the UDS calls to IS REST APIs.

    `name` is the host process caller name. This value must be unique per principal. If the caller is `idtype = module`, then the module identity is provisioned by IS in Azure IoT Hub with that `name`.

    `idtype` is an optional identity type returned to that host process associated with the IoT Hub identity type being returned to that host process - it is an array containing any combination of `device`, `module`, or `local`. Note that if `idtype` is not specified, the caller will be authorized to access all APIs (not just the host process APIs). It is also used by IS to provision identities with a specific `name` (when the caller's `idtype` contains `module`).

    > Note:  `idtype = device` is only used in special cases, but this support could be removed prior to GA.

2. OS configuration

    The host process package (using elevated admin privileges) needs to add OS userid, used by the host process to call IS APIs, in the `aziotid` group.


### Host process package configuration responsibilities

Generally, for host process modules, IS needs to be configured with a list of host process userid and module names. Based on its module list in `config.toml`, IS will reconcile module identities with IoT Hub on startup. The creation process is shown in the [Provisioning Flow diagram](img/est-ca-provisioning-simple.svg). Note that a device reprovision could also trigger re-creation of module identities.

For installation, the device administrator will initiate a host process package install (typically an elevated admin operation), which will install IS as a dependency. First, the IS package will install a `config.toml` configuration file with a default configuration file with no configured host processes. Then, the host process package install process (using elevated privileges) will add its respective host process userid into the `aziotid` group. Finally, the host process package install will configure its host process userid and name by placing its own `<package>.toml` (with a `[[principal]]` table entry as shown in IS configuration above) in the IS `/etc/aziot/identityd/config.d` override directory.
