# Overview

Azure IoT Edge brings the analytical power of the cloud closer to devices to drive better business insights and enable offline decision making through the use of [Edge modules](https://docs.microsoft.com/azure/iot-edge/iot-edge-modules).  The full IoT Edge runtime, in concert with IoT Hub, [provides numerous capabilities](https://docs.microsoft.com/azure/iot-edge/iot-edge-runtime) to scale out and manage an IoT solution from the cloud.  

The IoT Identity Service is one component of IoT Edge and can be used stand-alone.  The "Identity Service" is technically made up of three services (purple in the diagram) that provide provisioning and cryptographic services. They provide the foundation for authorized components on the device to communicate with Azure services (i.e. IoT Hub) whether as the [device](https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-identity-registry) or an individual [module](https://docs.microsoft.com/azure/iot-hub/iot-hub-devguide-module-twins).  Containerized modules (i.e. IoT Edge modules) require the full IoT Edge runtime. Non-containerized modules (i.e. host-level modules) minimally need the identity, cert, and key services described below.

- [Identity Service](identity-service.md)

    This service provisions the device identity and module identities with Azure. 

    The Identity Service provides access to both host-level processes and container modules (via the IoT Edge runtime) to connect to the cloud using tokens or X.509 certificate credentials, corresponding to their respective identities.

    Note that this service performs the entirety of provisioning.

- [Keys Service](keys-service.md)

    This service stores cryptographic keys, and allows callers to perform operations with those keys like encrypt, decrypt and sign. The service protects the keys by storing them in HSMs, and ensures that no operations against those keys export the keys to the device's memory.


- [Certificates Service](certificates-service.md)

    This service stores certificates, and allows callers to import and export them. Depending on the certificate issuance method, the Certificate Service may also provision certificates from a user-provided certificate issuer endpoint via a protocol like EST.


Each component talks to the other components via IPC in the form of HTTP-over-UDS.

![New component overview](img/new-component-overview-simple.svg)
[(Click here for detailed version)](img/new-component-overview-detailed.svg)

## Relation to IoT Edge

    The [IoT Edge runtime](https://docs.microsoft.com/azure/iot-edge/iot-edge-runtime) is responsible for interacting with a container engine to manage containerized IoT Edge modules. The code can be found in the [IoT Edge repo](https://github.com/azure/iotedge). It exposes APIs for those containerized Edge modules to request certificates, encrypt/decrypt secrets and obtain SAS tokens for talking to Azure IoT Hub. It implements these runtime operations by talking to the IS, CS and KS on behalf of the modules, ie it forwards these API requests to the identity, cert, and key services after enhancing them with the identity of the module making the request.


# Provisioning and Runtime Operation

This spec covers the following modes of provisioning and runtime operation.

- [Provisioning using EST, with certificates issued by EST (On-prem PKI)](est-ca.md)


# Misc

- [openssl engine internals](openssl-engine-internals.md)

- [Developer documentation](dev/_index.md)
