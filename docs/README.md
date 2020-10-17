# Overview

The IoT Identity Service provides various types of IoT identities and enables crypto operations needed for applications on edge devices. Components within [IoT Edge](https://aka.ms/iotedge) depend on the Identity Service.

- [Identity Service](identity-service.md)

    This service provisions [device](https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-identity-registry) identity and [module](https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-module-twins) identities with Azure. 

    The Identity Service enables containerized and non-containerized modules to connect to the cloud using tokens or X.509 certificate credentials, corresponding to their respective identities. Containerized modules (i.e. [IoT Edge modules](https://docs.microsoft.com/azure/iot-edge/iot-edge-modules)) require the full IoT Edge runtime. Non-containerized modules (i.e. host-level modules) minimally need the identity, cert, and key services described here.

    Note that this service performs the entirety of provisioning.


- [Keys Service](keys-service.md)

    This service stores cryptographic keys, and allows callers to perform operations with those keys like encrypt, decrypt and sign. The service protects the keys by storing them in HSMs, and ensures that no operations against those keys export the keys to the device's memory.


- [Certificates Service](certificates-service.md)

    This service stores certificates, and allows callers to import and export them. Depending on the certificate issuance method, the Certificate Service may also provision certificates from a user-provided certificate issuer endpoint via a protocol like EST.


Each component talks to the other components via IPC in the form of HTTP-over-UDS.

![New component overview](img/new-component-overview-simple.svg)
[(Click here for detailed version)](img/new-component-overview-detailed.svg)

## Relation to IoT Edge

The full IoT Edge runtime, in concert with IoT Hub, [provides numerous capabilities](https://docs.microsoft.com/azure/iot-edge/iot-edge-runtime) that are needed to scale out and manage an IoT solution from the cloud. The code for IoT Edge can be found in its [repo](https://github.com/azure/iotedge). 

IoT Edge exposes APIs for [Edge modules](https://docs.microsoft.com/azure/iot-edge/iot-edge-modules) to request certificates, encrypt/decrypt secrets and obtain SAS tokens for talking to Azure IoT Hub. It implements these runtime operations by talking to the IS, CS and KS on behalf of the containerized modules, ie it forwards these API requests to the identity, cert, and key services after enhancing them with the identity of the module making the request.

# Provisioning and Runtime Operation

This spec covers the following modes of provisioning and runtime operation.

- [Provisioning using EST, with certificates issued by EST (On-prem PKI)](est-ca.md)


# Misc

- [openssl engine internals](openssl-engine-internals.md)

- [Developer documentation](dev/index.md)
