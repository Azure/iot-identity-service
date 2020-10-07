# Overview

IoT Edge is used to provision a device with Azure and deploy modules to the device. To this end, it is responsible for provisioning the device and module identities, managing the lifetime of the device identity certificate, and providing cryptographic services to modules so that they can store secrets and obtain authentication tokens to talk to Azure services.

In IoT Edge v1, provisioning and cryptographic services were all provided by a single monolithic service running in the `iotedged` process. IoT Edge v2 is made up of several independent services instead:

- [Identity Service](identity-service.md)

    This service provisions the device identity and module identities with Azure. Depending on the device provisioning method, the Identity Service also provisions the device identity and module identity certificates from a user-provided certificate issuer endpoint via a protocol like EST. 

    The Identity Service provides access to device processes and modules to connect to the cloud using tokens or X.509 certificate credentials, corresponding to their respective identities.

    Note that this service performs the entirety of provisioning.

- [Keys Service](keys-service.md)

    This service stores cryptographic keys, and allows callers to perform operations with those keys like encrypt, decrypt and sign. The service protects the keys by keeping them in HSMs, and ensures that no operations against those keys export the keys to the device's memory.


- [Certificates Service](certificates-service.md)

    This service stores certificates, and allows callers to import and export them. Depending on the device provisioning method, the Certificate Service may also provision workload certificates from a user-provided certificate issuer endpoint via a protocol like EST.


Each component talks to the other components via IPC in the form of HTTP-over-UDS.

![New component overview](img/new-component-overview-simple.svg)
[(Click here for detailed version)](img/new-component-overview-detailed.svg)


# Provisioning and Runtime Operation

This spec covers the following modes of provisioning and runtime operation.

- [Provisioning using EST, with certificates issued by EST (On-prem PKI)](est-ca.md)


# Misc

- [openssl engine internals](openssl-engine-internals.md)

- [Developer documentation](dev/_index.md)
