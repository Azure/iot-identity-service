# Using EST with Certificates Service

This document covers how to configure Certificates Service to issue certificates over EST.

## Prerequisites

- Certificates Service and Keys Service configured and running
- A working EST server that processes enrollment requests

## Configuration Options

EST certificate issuance is configured in Certificates Service's config.toml, which by default is `/etc/aziot/certd/config.toml` or a file in `/etc/aziot/certd/config.d/`.

The global `[cert_issuance.est]` section controls options that apply to all certificates issued over EST.

Each certificate has a `[cert_issuance]` entry. By specifying `method = "est"`, the corresponding certificate will be issued over EST.

```toml
# Global options that affect all EST-issued certificates.
[cert_issuance.est]

# Trusted root certificates to validate the EST server's TLS certificate;
# optional depending on how the EST server is configured.
# It is not required for servers with a publicly-rooted TLS certificate.
trusted_certs = ["cert-id"]

# Provides a default URL if the EST URL is not provided for a certificate.
# Optional if each certificate issuance specifies a URL.
[cert_issuance.est.urls]
default = "https://est.example.com/.well-known/est"

# Below are options for authenticating with the EST server. The required options will depend on the EST
# server's configuration. These global settings apply to all certificates that don't configure auth separately.
[cert_issuance.est.auth]

# Authentication with TLS client certificate. Provide the cert ID of the client cert and its corresponding
# private key. Note that the aziotcs user must be authorized to access `identity_pk` in Keys Service.
identity_cert = "identity-cert-id"
identity_pk = "identity-cert-pk-id"

# Authentication with a TLS client certificate which will be used once to create the initial certificate.
# After the first certificate issuance, an identity_cert and identity_pk will be automatically created and
# used. Provide the cert ID of the bootstrap client cert and its corresponding private key. Note that the
# aziotcs user must be authorized to access `bootstrap_identity_pk` in Keys Service.
bootstrap_identity_cert = "bootstrap-identity-cert-id"
bootstrap_identity_pk = "bootstrap-identity-pk-id"

# Authentication with username and password.
username = "username"
password = "password"

# Sample configuration of a single EST-issued certificate.
# Replace `name` with the desired certificate name.
[cert_issuance.name]

# Identifies this certificate as being issued over EST.
method = "est"

# Optional certificate common name. Defaults to the CSR's common name if not provided.
common_name = "common name"

# Optional number of days between certificate issuance and expiry. Defaults to 30 if not provided.
expiry_days = 30

# Optional EST URL to issue this certificate. Defaults to the `default` URL in `[cert_issuance.est.urls]`
# if not provided. The URL must be provided either here or in default, i.e. certd will fail if no URL is
# provided here and no default exists.
url = "https://est.example.com/.well-known/est"

# It is also possible to configure auth separately for each certificate. The options are the
# same as in the global EST configuration and override the global configuration for their corresponding
# certificate.
identity_cert = "identity-cert-id"
identity_pk = "identity-cert-pk-id"

bootstrap_identity_cert = "bootstrap-identity-cert-id"
bootstrap_identity_pk = "bootstrap-identity-pk-id"

username = "username"
password = "password"
```

## Sample Configuration

Below are sample configuration files that can be used as starting points to test EST certificate issuance.

The certd configuration file configures EST certificate issuance.

`/etc/aziot/certd/config.d/test-est-cert.toml`

```toml
# Configure the trusted root CA certificate in the global EST options. This section is optional
# if the EST server's TLS certificate is already trusted by the system's CA certificates.
[cert_issuance.est]
trusted_certs = ["est-server-ca"]

[cert_issuance.est.urls]

[preloaded_certs]
est-server-ca = "file:///path/to/file.pem"

# Configure the issuance of the EST test certificate.
[cert_issuance.test-est-cert]
method = "est"

# Example with the EST path segment `test-est-cert` in the URL.
# The path will depend on server configuration.
url = "https://est.example.com/.well-known/est/test-est-cert"

# This example will use the EST bootstrap certificate and key to authenticate,
# but a cert and key ID for the identity certificate must still be provided.
# These credentials will automatically be created, so it is sufficient to provide
# a set of unique IDs that will not be used for any other credentials.
identity_cert = "test-est-cert-identity-id"
identity_pk = "test-est-cert-identity-id"

# The credentials to use upon initial authentication with the EST server.
# After that, certd will automatically create, use, and renew identity_cert and identity_pk.
bootstrap_identity_cert = "test-est-bootstrap-cert-id"
bootstrap_identity_pk = "test-est-bootstrap-key-id"

# Load the bootstrap certificate from a file into certd.
# This file must be readable by aziotcs.
[preloaded_certs]
test-est-bootstrap-cert-id = "file:///path/to/file.pem"

# Allow the specified user to create this certificate.
# Replace `1000` with the relevant user ID. Note that the root user has access to all certificates.
[[principal]]
uid = 1000
certs = ["test-est-cert"]
```

The keyd configuration file authorizes aziotcs to access the required keys.

`/etc/aziot/keyd/config.d/test-est-cert.toml`

```toml
# Load the bootstrap certificate key from a file into key.
# This file must be readable by aziotks.
[preloaded_keys]
test-est-bootstrap-key-id = "file:///path/to/file.pem"

# Authorize aziotcs to access the necessary keys.
[[principal]]
# Replace with output of `id -u aziotcs`
uid = 997

# Should contain the key IDs of bootstrap_identity_pk and identity_pk.
keys = ["test-est-bootstrap-key-id", "test-est-cert-identity-id"]
```

## Testing EST on the command line

After configuring Certificates Service, you can test certificate issuance over EST from the command line. Generate a CSR and make a request to Certificates Service to create a new certificate.

```sh
# Generate a key for CSR.
openssl genrsa -out key.pem

# Generate CSR. Note that the common name must be provided either here in the CSR
# or in certd's configuration.
#
# This command generates a simple CSR that doesn't have attributes or other useful
# information. For a production certificate, you will likely need to add attributes
# or configure the EST server to automatically issue certificates with the required
# attributes.
openssl req -new -key key.pem -subj "/CN=test-est-cert" -out req.pem

# Make the request to Certificates Service.
# The user making this request must be root or in the aziotcs group.
# For a non-root user, the uid must match the uid in certd's authorized principals
# (1000 in the example above).
#
# The request schema is:
# {
#     "certId": "<cert name>",
#     "csr": "<generated CSR with newlines escaped>"
# }
curl --unix-socket /run/aziot/certd.sock http://localhost/certificates?api-version=2020-09-01 \
    -H "content-type: application/json" \
    --data "$(jq -cn --arg 'certId' 'test-est-cert' --arg 'csr' "$(cat req.pem)" '{"certId": $certId, "csr": $csr}')"
```

You should receive the newly-issued certificate as the output of the last command.

If you see error messages from either Keys Service or Certificates Service that begin with `user _ is not authorized...`, check the authorized `[[principal]]` list in the keyd and certd configuration files.
