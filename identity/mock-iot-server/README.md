# mock-iot-server

mock-iot-server provides a subset of DPS server and IoT Hub functionality for testing. In its current form, it is *not* a substitute for testing with a real DPS or IoT Hub.
 - Does not verify any client credentials
 - May return the same hardcoded responses to all clients
 - May panic on error

## Arguments

Required arguments:
 - `--port`: Port to listen on. Hostname is always `localhost`.
 - `--server-cert-chain`: Path to server cert chain, starting with the leaf and ending with the root.
 - `--server-key`: Server cert key.

Optional arguments:
 - `--trust-bundle-certs-dir`: Directory of DPS trust bundle certificates. The trust bundle will contain all parsable certificates in this directory.
 - `--enable-identity-certs`: Enable DPS identity certificate issuance.
 - `--enable-server-certs`: Enable DPS server certificate issuance.

## TLS server certificate

Since Azure only accepts requests over TLS, mock-iot-server needs a TLS server certificate. See [mock-iot-cert-gen.sh](../../ci/mock-iot-tests/mock-iot-cert-gen.sh) for an example on how to generate a root CA certificate and TLS server certificate for mock-iot-server.

mock-iot-server's root CA certificate must be installed to the system's root CA certificate store.
