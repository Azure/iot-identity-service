# Using DPS-provided certificates with Identity Service

As of the `2021-11-01-preview` API version, DPS supports management and issuance of certificates alongside provisioning. This document describes how Identity Service supports:
* DPS-managed trust bundles
* DPS-issued identity certificates

Documentation on configuring DPS with trust bundles and identity certificates is [here](**TODO: replace with link when available**).

## Trust Bundle

The trust bundle is a set of trusted CA certificates. DPS can provide the trust bundle along with device information when provisioning. If Identity Service receives a trust bundle from DPS, it will save the trust bundle with Certificates Service.

### Setting Trust Bundle Name

Identity Service saves the trust bundle with the name `aziot-dps-trust-bundle` by default. You can override the default name in `/etc/aziot/config.toml` by setting the configuration option `dps_trust_bundle`.

```toml
dps_trust_bundle = "aziot-dps-trust-bundle"
```

If Identity Service receives a trust bundle and `dps_trust_bundle` is not specified, it will save the trust bundle using the default name `aziot-dps-trust-bundle`. The `dps_trust_bundle` setting has no effect when not provisioned using DPS.

### Retrieving the Trust Bundle

Once provisioning is complete and the trust bundle is in Certificates Service, it can be retrieved by making a request to Certificates Service.

For example, to retrieve a trust bundle named `aziot-dps-trust-bundle` using curl:
```sh
curl --unix-socket /run/aziot/certd.sock http://localhost/aziot-dps-trust-bundle?api-version=2020-09-01
```

Applications can then install the trust bundle to their trusted root CA certificate store.

### Updating the Trust Bundle

DPS currently does not provide a method for a client to automatically update a trust bundle. Therefore, if the trust bundle is updated in DPS, the device must be reprovisioned.

This can be done with `iotedge system reprovision` or `aziotctl system reprovision`.

### Trust Bundle and IoT Edge

The IoT Edge daemon `aziot-edged` automatically provides DPS-managed trust bundles to IoT Edge modules through its `/trust-bundle` API. If the customer has configured a trust bundle in IoT Edge as well, then IoT Edge will combine the CA certificates from the locally-configured and DPS-provided trust bundles (after removing duplicates), and create a combined trust bundle which is then used by applications on the Edge device.

## Identity Certificate

DPS-issued identity certificates replace token-based authentication when Identity Service communicates with IoT Hub. Identity Service manages these certificates without user intervention, retrieving and renewing them as necessary.

Previously, the identity certificates needed to be loaded onto a device manually and were not supported when using SAS-token based provisioning. With the `2021-11-01-preview` DPS API version, DPS provides identity certificates to Identity Service with device information.

### Configuration

Support for DPS-issued identity certificates does not change the format of Identity Service's `config.toml`. However, the use of the configuration-specified DPS credentials when using DPS X.509-based provisioning has changed.

Previously, Identity Service used the configuration-specified DPS credentials `identity_pk` and `identity_cert` to communicate with both DPS and IoT Hub. With DPS-issued identity certificates, Identity Service only uses the configuration-specified `identity_cert` and `identity_pk` to communicate with DPS. The DPS-issued identity certificates replace `identity_cert` and `identity_pk` when communicating with IoT Hub.

Additionally, when using DPS SAS-based provisioning, Identity Service used a token generated from the SAS key to authenticate with both DPS and IoT Hub. With DPS-issued identity certificates, Identity Service uses token authentication only with DPS; the DPS-issued identity certificates likewise replace tokens for authentication with IoT Hub.

### Retrieval and Renewal

Identity Service stores a DPS-issued identity certificate and its key using the special names `aziot-dps-identity-cert` and `aziot-dps-identity-cert-key`, respectively. It will automatically retrieve these credentials as needed, and renews the identity certificate with DPS when it expires.
