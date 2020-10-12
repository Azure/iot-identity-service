# API

## Get primary cloud identity for authenticated workload
`GET /identities/identity`

### Response for principals associated to device identities (SAS case)
```json
{
  "type": "aziot",
  "spec": 
  {
    "hubname": "myhub.net",
    "deviceid": "device01",
    "auth": {
        "type": "sas",
        "keyHandle": "string"
    }
  }
}
```

### Response for principals associated to device identities (X.509 case)

```json
{
  "type": "aziot",
  "spec" : 
  {
    "hubname": "myhub.net",
    "deviceid": "device01",
    "auth": {
        "type": "x509",
        "keyHandle": "string",
        "certId": "string"
    }
  }
}
```

### Response for principals associated to module identities (SAS case)
```json
{
  "type": "aziot",
  "spec": 
  {
    "hubname": "myhub.net",
    "deviceid": "device01",
    "moduleid": "module01",
    "genid": "12345",
    "auth": {
        "type": "sas",
        "keyHandle": "string"
   }
  }
}
```

### Response for principals associated to module identities (X.509 case)
```json
{
  "type": "aziot",
  "spec": 
  {
    "hubname": "myhub.net",
    "deviceid": "device01",
    "moduleid": "module01",
    "genid": "12345",
    "auth": {
        "type": "x509",
        "keyHandle": "string",
        "certId": "string"
    }
  }
}
```

The response depends on the principal used to authenticate with the Identity Service. The `idtype` in IS [configuration](is-operation.md) determines the type of identity returned by this API. 
`keyHandle` is used with KS. For `aziot`-type identities using SaS auth, `keyHandle` contains the key handle of the identity's primary shared access key, which can be used to generate a security token (for IoT Hub authentication) using the KS `sign` operation. For `aziot`-type device identities using X.509 auth, `keyHandle` contains the key handle of the identity X.509 certificate's private key, used for IoT Hub client authentication during TLS handshake using an SSL engine.    
`certId` contains the certificate ID of the identity X.509 certificate, which can be retrieving used using CS while connecting to IoT Hub.

---

## Get IoT device provisioning result

`GET /identities/device`

### Response (SAS case)
```json
{
  "type": "aziot",
  "spec": 
  {
    "hubname": "myhub.net",
    "deviceid": "device01",
    "auth": {
        "type": "sas",
        "keyHandle": "string"
    }
  }
}
```

### Response (X.509 case)

```json
{
  "type": "aziot",
  "spec" : 
  {
    "hubname": "myhub.net",
    "deviceid": "device01",
    "auth": {
        "type": "x509",
        "keyHandle": "string",
        "certId": "string"
    }
  }
}
```

---

## List IoT Module Identities
`GET /identities/modules`

### Response (SAS case)
```json
{
  "identities": [
    {
      "type": "aziot",
      "spec": 
      {
        "hubname": "myhub.net",
        "deviceid": "device01",
        "moduleid": "module01",
        "genid": "12345",
        "auth": {
            "type": "sas",
            "keyHandle": "string"
        }
      }
    }
  ]
}
```

### Response (X.509 case)

```json
{
  "identities": [
    {
      "type": "aziot",
      "spec": 
      {
        "hubname": "myhub.net",
        "deviceid": "device01",
        "moduleid": "module01",
        "genid": "12345",
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

## Create IoT module identity
`POST /identities/modules`

### Request
```json
{
  "type": "aziot",
  "name": "module01",
  "deviceid": "device01",
  "managedBy": "edgeruntime"
}
```

### Response (SAS case)
```json
{
  "type": "aziot",
  "spec": 
  {
    "hubname": "myhub.net",
    "deviceid": "device01",
    "moduleid": "module01",
    "genid": "12345",
    "auth": {
        "type": "sas",
        "keyHandle": "string"
   }
  }
}
```

### Response (X.509 case)
```json
{
  "type": "aziot",
  "spec": 
  {
    "hubname": "myhub.net",
    "deviceid": "device01",
    "moduleid": "module01",
    "genid": "12345",
    "auth": {
        "type": "x509",
        "keyHandle": "string",
        "certId": "string"
    }
  }
}
```

---

## Get IoT module identity information
`GET /identities/modules/{module-id}`

### Response (SAS case)
```json
{
  "type": "aziot",
  "spec": 
  {
    "hubname": "myhub.net",
    "deviceid": "device01",
    "moduleid": "module01",
    "genid": "12345",
    "auth": {
        "type": "sas",
        "keyHandle": "string"
   }
  }
}
```

### Response (X.509 case)
```json
{
  "type": "aziot",
  "spec": 
  {
    "hubname": "myhub.net",
    "deviceid": "device01",
    "moduleid": "module01",
    "genid": "12345",
    "auth": {
        "type": "x509",
        "keyHandle": "string",
        "certId": "string"
    }
  }
}
```

---

## Delete IoT module identity
`DELETE /identities/modules/{module-id}`

### Response
```
204 No Content
```

---

## Trigger IoT device reprovisioning flow
`POST /identities/device/reprovision`

### Request
```json
{
  "type": "aziot"
}
```

### Response
```
200 Ok
```
--

# Notes on IS operations

## Module Provisioning / Re-provisioning

IoT Hub module identities will get generated by Identity service (IS) for containerized and host process workloads. Once the device identity is provisioned by IS, the IS can begin generating module identities associated with that device identity. There are two steps to configure IS to start generating module identities - 

1. IS configuration

    ```toml
    [[principal]]
    uid = 1001
    name = "hostdaemon1"

    [[principal]]
    uid = 1002
    name = "hostprocess1"
    idtype = "device"

    [[principal]]
    uid = 1003
    name = "hostprocess2"
    idtype = "module"
    ```

    The table of principal accounts in IS configuration represents all the host process callers of IS APIs (known as `principal`s) and their corresponding OS userid. 

    `uid` is the OS userid that will be included in the UDS calls to IS REST APIs. This value must be unique per principal. 

    `name` is the host process caller name. If the caller is `idtype = module`, then the module identity is provisioned by IS in Azure IoT Hub with that `name`. 
    
     > Note:  `idtype = device` is only used in special cases, but this support could be removed prior to GA.
    
    `idtype` is an optional identity type returned to that host process associated with the IoT Hub identity type being returned to that host process - it is either `device` identity or `module` identity. Note that if `idtype` is not specified, the caller will be authorized to access all APIs (not just the host process APIs). It is also used by IS to provision identities with a specific `name` (when the caller has `idtype = module`).  
    
2. OS configuration

    The host process package (using elevated admin privileges) needs to add OS userid, used by the host process to call IS APIs, in the `aziotid` group. See [Packaging](packaging.md) for more details on `aziot` package.


## Host process package configuration responsibilities

Generally, for host process modules, IS needs to be configured with a list of host process userid and module names. Based on its module list in `config.toml`, IS will reconcile module identities with IoT Hub on startup. The creation process is shown in the [Provisioning Flow diagram](est-ca-provisioning-simple.plantuml). Note that a device reprovision could also trigger re-creation of module identities. 

For installation, the device administrator will initiate a host process package install (typically an elevated admin operation), which will install IS as a dependency. First, the IS package will install a `config.toml` configuration file with a default configuration file with no configured host processes. Then, the host process package install process (using elevated privileges) will add it's respective host process userid into the `aziotid` group. Finally, the host process package install will configure it's host process userid and name in the IS `config.toml` (as shown in IS configuration above). 

