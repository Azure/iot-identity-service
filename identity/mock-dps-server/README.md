# mock-dps-server

mock-dps-server provides a subset of DPS server functionality for testing. In its current form, it is *not* a substitute for testing with the real DPS.
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

## TLS server certificate

Since DPS only accepts requests over TLS, mock-dps-server needs a TLS server certificate. See [mock-dps-cert-gen.sh](../../ci/mock-dps-tests/mock-dps-cert-gen.sh) for an example on how to generate a root CA certificate and TLS server certificate for mock-dps-server.

mock-dps-server's root CA certificate must be installed to the system's root CA certificate store.
