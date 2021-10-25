# Using DPS-provided certificates with Identity Service

As of the `2021-11-01-preview` API version, DPS supports management and issuance of certificates alongside provisioning. This document describes how Identity Service uses DPS-managed trust bundles and DPS-issued identity certificates.

Documentation on configuring DPS with trust bundles and identity certificates is [here](**TODO: replace with link when available**).

## Trust Bundle

The trust bundle is a set of trusted root CA certificates that DPS can provided with device information when provisioning. If Identity Service receives a trust bundle from DPS, it will save the trust bundle with Certificates Service.

### Setting Trust Bundle Name

The configuration option `dps_trust_bundle` provides the name used for the trust bundle. Specify it in `/etc/aziot/config.toml`.

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

### Trust Bundle and IoT Edge

The IoT Edge daemon `aziot-edged` automatically provides DPS-managed trust bundles to IoT Edge modules through its `/trust-bundle` API. IoT Edge joins the certificates in the DPS-managed trust bundle with its other trust bundle certificates (such as the Edge CA certificate), and provides the resulting set of certificates to modules. IoT Edge will also remove duplicate certificates from this set.

## Identity Certificate

DPS-issued identity certificates replace token-based authentication when Identity Service communicates with IoT Hub. Identity Service manages these certificates without user intervention, retrieving and renewing them as necessary.

Previously, the identity certificates needed to be loaded onto a device manually and were not supported when using SAS-token based provisioning. With the `2021-11-01-preview` DPS API version, DPS provides identity certificates to Identity Service with device information.

### Configuration

Support for DPS-issued identity certificates does not change the format of Identity Service's `config.toml`. However, the use of the configuration-specified DPS credentials when using DPS X.509-based provisioning has changed.

Previously, Identity Service used the configuration-specified DPS credentials `identity_pk` and `identity_cert` to communicate with both DPS and IoT Hub. With DPS-issued identity certificates, Identity Service only uses the configuration-specified `identity_cert` and `identity_pk` to communicate with DPS. The DPS-issued identity certificates replace `identity_cert` and `identity_pk` when communicating with IoT Hub.

Additionally, when using DPS SAS-based provisioning, Identity Service used a token generated from the SAS key to authenticate with both DPS and IoT Hub. With DPS-issued identity certificates, Identity Service uses token authentication only with DPS; the DPS-issued identity certificates likewise replace tokens for authentication with IoT Hub.

### Retrieval and Renewal

Identity Service stores a DPS-issued identity certificate and its key using the special names `aziot-dps-identity-cert` and `aziot-dps-identity-cert-key`, respectively. It will automatically retrieve these credentials as needed, and renews the identity certificate with DPS when it expires.
