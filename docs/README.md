# Overview

The IoT Identity Service package provides provisioning and cryptographic services for Azure IoT devices. This includes both regular Azure IoT devices and Azure IoT Edge devices.

The package is made up of three services:

- [Identity Service](identity-service.html)

    This service provisions the device's [identity](https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-identity-registry) with Azure. The device identity can be based on symmetric keys or X.509 certificates, and be used with manual device registrations, DPS individual enrollments or DPS group enrollments.

    The Identity Service also provides access to native processes ("host processes") to connect to the cloud. Depending on how the user configures the Identity Service, host processes can get their own *module identities* provisioned by the Identity Service, or use the device identity, or both.


- [Keys Service](keys-service.html)

    This service stores cryptographic keys, and allows callers to perform operations with those keys like encrypt, decrypt and sign. The service protects the keys by storing them in HSMs, and ensures that no operations against those keys export the keys to the device's memory.

- [TPM Service](tpm-service.md)

    This service brokers access to a device's TPM, and allows callers to retrieve the TPM's endorsement and storage root keys, activate a new identity key, and sign data using a stored identity key. The TPM service is the only service with permissions to access the TPM, and exposes an API which ensures the integrity of the keys stored in the TPM.

- [Certificates Service](certificates-service.html)

    This service stores certificates, and allows callers to import and export them. Depending on the certificate issuance method, the Certificate Service may also provision certificates from a user-provided certificate issuer endpoint via a protocol like EST.


# Relationship with IoT Edge

For IoT Edge devices, module identity provisioning and cryptographic services used to be provided by the IoT Edge runtime. Now the IoT Edge runtime defers to these three services to provide those features. In other words, the Identity Service is also responsible for provisioning module identities for IoT Edge modules, and the Keys Service and Certificates Service handle keys and certificates that the modules use via the IoT Edge Workload API. These three services are automatically installed as a dependency when installing the IoT Edge package.

Note that IoT Edge modules run in containers and thus do not communicate with the three services directly. They still only communicate with the IoT Edge runtime as before via the IoT Edge Management and Workload APIs, and their requests are forwarded by the IoT Edge runtime to the three services on the modules' behalf. Refer to <https://github.com/Azure/iotedge> for more details about the IoT Edge runtime.


Each component talks to the other components via IPC in the form of HTTP-over-UDS.

![New component overview](img/new-component-overview-simple.svg)
[(Click here for detailed version)](img/new-component-overview-detailed.svg)


# Provisioning and Runtime Operation

This spec covers the following modes of provisioning and runtime operation.

- [Provisioning using EST, with certificates issued by EST (On-prem PKI)](est-ca.html)


# Misc

- [Developer documentation](dev/index.html)

- [Openssl engine internals](openssl-engine-internals.html)
