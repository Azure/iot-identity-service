# Configuring and running `aziot-certd`

A basic configuration looks like:

```toml
homedir_path = "/var/lib/aziot/certd"

[cert_issuance]

[preloaded_certs]

[endpoints]
aziot_certd = "unix:///var/lib/aziot/certd.sock"
aziot_keyd = "unix:///var/lib/aziot/keyd.sock"
```

- `homedir_path` - This is the home directory of the service, and where dynamically generated cert files will be stored. Ensure that this directory exists, and that it is readable and writable by the user you will run the service as.

- `[cert_issuance]` - This section defines how dynamically-generated certs should be issued. It is a map of cert IDs to the options used to issue certificates.

    It also contains optional `[cert_issuance.local_ca]` and `[cert_issuance.est]` subsections to configure parameters of those issuance methods.

    Each certificate ID maps to a struct of options. Currently supported certificate options are:
    - `method`: Method of cert issuance. Always required. Valid values are `"est`, `"local_ca"`, or `"self_signed"`.
    - `common_name`: Common name for certificate. Optional; if not provided, CSR subject or a default provided by aziot-certd is used. Applies to all methods.
    - `expiry_days`: Number of days between certificate issuance and expiry. Applies to `self_signed` and `local_ca` methods only.

- `[preloaded_certs]` - This section defines preloaded certs as a map of cert ID to URI. For example, if you have a device ID cert file that you want the service to make available to the other components, you would register that file in this section.

    Only `file://` URIs are supported at this time. Files must be in PEM format and can contain one or more certificates.

- `[endpoints]` - This section defines endpoints for the services. For this service, there are two endpoints:

    - The `aziot_keyd` value denotes the endpoint that the `aziot-keyd` service is accepting connections on (the same value as its own `endpoints.aziot_keyd` config)

    - The `aziot_certd` value denotes the endpoint that this service will accept connections on.

    Endpoints can be `unix` URIs where the URI contains a path of a UDS socket that the service will bind to, or an `http` URI with a host (and optional port) that the service will bind a TCP socket to.

Save this file to any location that is readable by the user you will run the service as. The service looks for this file by default at `/etc/aziot/certd/config.toml`, but it can be given a different path by setting the `AZIOT_CERTD_CONFIG` env var.

With this basic file, fill it out depending on what workflow you want to test:


1. Device CA cert is...

    1. ... dynamically generated locally and self-signed.

        ```toml
        [cert_issuance]
        device-ca = { method = "self_signed" }
        workload-ca = { method = "local_ca" }

        [cert_issuance.local_ca]
        cert = "device-ca"
        pk = "device-ca"
        ```

    1. ... pre-created on the filesystem and preloaded into the service.

        ```toml
        [cert_issuance]
        workload-ca = { method = "local_ca" }

        [cert_issuance.local_ca]
        cert = "device-ca"
        pk = "device-ca"

        [preloaded_certs]
        device-ca = "file:///path/to/device-ca.pem"
        ```

    1. ... issued by an EST server.

        ```toml
        [cert_issuance]
        device-ca = { method = "est" }
        workload-ca = "local_ca"

        [cert_issuance.local_ca]
        cert = "device-ca"
        pk = "device-ca"

        [cert_issuance.est]
        ...

        [cert_issuance.est.urls]
        device-ca = "https://127.0.0.1:8085/.well-known/est"
        ```

    1. ... issued with custom options instead of the defaults.

        ```toml
        [cert_issuance]
        device-ca = { method = "est", common_name = "custom-name-1" }
        workload-ca = { method = "local_ca", expiry_days = 90, common_name = "custom-name-2" }
        ```

1. Device ID cert is...

    1. ... not used. The device authenticates to IoT Hub using a SAS key. This is the case with a IoT Device identity using the `shared_private_key` auth method.

    1. ... pre-created on the filesystem and preloaded into the service.

        ```toml
        [preloaded_certs]
        device-id = "file:///path/to/device-id.pem"
        ```

    1. ... issued by a device ID CA cert that has been preloaded into the service. This is the case with a IoT Device identity using the `x509_ca` auth method.

        ```toml
        [preloaded_certs]
        device-id-ca = "file:///path/to/device-id-ca.pem"
        ```

    1. ... issued by the device CA cert. This can be the case with a IoT Device identity using the `x509_ca` auth method, and the CA uploaded to IoT Hub is a root of every device's device CA cert.

        ```toml
        [cert_issuance]
        device-id = "local_ca"
        ```

    1. ... issued by an EST server.

        ```toml
        [cert_issuance]
        device-id = { method = "est" }

        [cert_issuance.est]
        ...

        [cert_issuance.est.urls]
        device-id = "https://127.0.0.1:8085/.well-known/est"
        ```

1. EST server is...

    1. ... not used.

    1. ... used with basic auth.

        ```toml
        [cert_issuance.est]
        username = "estuser"
        password = "estpwd"
        ```

    1. ... used with X509 auth, with a preloaded EST identity cert.

        ```toml
        [cert_issuance.est]
        identity_cert = "est-id"
        identity_pk = "est-id"

        [preloaded_certs]
        est-id = "file:///path/to/est-id.pem"
        ```

    1. ... used with X509 auth, with a preloaded bootstrap EST identity cert.

        ```toml
        [cert_issuance.est]
        identity_cert = "est-id"
        identity_pk = "est-id"
        bootstrap_identity_cert = "est-bootstrap-id"
        bootstrap_identity_pk = "est-bootstrap-id"

        [preloaded_certs]
        est-bootstrap-id = "file:///path/to/est-bootstrap-id.pem"
        ```

    Note:

    - An EST server can be configured to require both basic auth (`username` and `password`) as well as a TLS client cert (`identity_cert` and `identity_pk`). Set all four fields in this case.

    - When using X509 auth, the `identity_cert` and `identity_pk` identify the cert ID and private key ID of the EST identity cert. If they are preloaded, they will be used.

        If they are not preloaded, the `bootstrap_identity_cert` and `bootstrap_identity_pk` fields must be set to the cert ID and private key ID of the bootstrap client cert. This bootstrap client cert is used once, to authenticate with the EST server and issue a new EST identity cert. This new EST identity cert is used for all future EST server requests.

        Note that, in this latter case, the `identity_cert` and `identity_pk` fields are still set. Their values will be used to persist the new EST identity cert.

    - The `[cert_issuance.est.urls]` section is a map of cert IDs to EST endpoint URLs. This is required in the case where a particular EST endpoint only issues a single kind of cert, say CA certs, while another EST endpoint only issues another kind of cert, say client certs. Therefore you would want the device CA cert to be issued by the former and the device ID cert to be issued by the latter.

        Note that all the endpoints share the same client authentication.

    - If the EST server's own cert is not chained to the device's root of trust, its CA can be preloaded and designated for this purpose by setting the `cert_issuance.est.trusted_certs` field.

        ```toml
        [cert_issuance.est]
        trusted_certs = [
            "est-ca",
        ]

        [preloaded_certs]
        "est-ca" = "file:///path/to/est/ca/cert.pem"
        ```

1. Finally, run the service.

    As mentioned at the beginning, if your config file is not saved at `/etc/aziot/certd/config.toml`, set the `AZIOT_CERTD_CONFIG` env var to its actual path.

    ```sh
    export AZIOT_CERTD_CONFIG='...'

    cargo run -p aziot-certd
    ```

    The service will remain running.


## Running an EST server locally

[The libest repository](https://github.com/cisco/libest) contains a simple EST server which can be run locally. Follow its instructions to build and run it.

Since the server's cert (`example/server/estCA/cacert.crt`) is untrusted, you'll need to follow the note above to add it to `cert_issuance.est.trusted_certs`

Note that the server uses an openssl configuration at `example/server/estExampleCA.cnf` to set the issued certs' attributes. In order to issue CA certs via this server, you need to change this file to not disable the CA basic constraint.

```diff
 # This goes against PKIX guidelines but some CAs do it and some software
 # requires this to avoid interpreting an end user certificate as a CA.
-basicConstraints=CA:FALSE
-keyUsage=digitalSignature
 crlDistributionPoints=URI:http://example.com/crl.pem
 # Add the id-kp-cmcRA usage.  This isn't defined in OpenSSL, so we
 # Need to use the OID value
```
