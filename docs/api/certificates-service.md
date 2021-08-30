# Certificates Service

## API

An OpenAPI v3 spec for this service can be found at `/cert/aziot-certd/openapi/2020-09-01.yaml`

Note: For both requests and responses, the PEM string can contain multiple certificates. This happens when the certificates form a chain where the first cert is the leaf cert.

### Create New Certificate from CSR

`POST /certificates?api-version=2020-09-01`

#### Authentication

Required. See [API authentication](#api-authentication).

#### Request

```json
{
    "certId": "...",
    "csr": "base64-encoded-string",
    "issuer": {
        "certId": "...",
        "privateKeyHandle": "..."
    }
}
```

`issuer` is ignored (and thus need not be specified) if the CS is configured to issue the requested certificate via an external service using EST protocol.

#### Response

```json
{
    "pem": "string"
}
```

---

### Import Certificate

`PUT /certificates/{certId}?api-version=2020-09-01`

#### Authentication

Required. See [API authentication](#api-authentication).

#### Request

```json
{
    "pem": "string"
}
```

#### Response

```json
{
    "pem": "string"
}
```

---

### Get Existing Certificate

`GET /certificates/{certId}?api-version=2020-09-01`

#### Authentication

Not required.

#### Response

```json
{
    "pem": "string"
}
```

---

### Delete Existing Certificate

`DELETE /certificates/{certId}?api-version=2020-09-01`

#### Authentication

Required. See [API authentication](#api-authentication).

#### Response

HTTP 204 No Content

---

## API authentication

APIs that modify certificates require the caller to authenticate with CS. Allowed callers are listed in the CS config directory, `/etc/aziot/certd/config.d`.

Each file in the CS config directory should list allowed Unix user IDs (UIDs) and the certificates that those users may access. The file name does not matter, but files must have the extension `.toml`. Only files directly under the config directory are parsed (i.e. the config directory is not searched recursively).

For example, `/etc/aziot/certd/config.d/example.toml`:
```toml
# Each user should be listed as a [[principal]]
# This principal grants user 1000 write access to the 'example1' and 'example2' certificates.
[[principal]]
uid = 1000
certs = ["example1", "example2"]

# Wildcards may also be used for certificate IDs.
# This principal grants user 1001 access to all certificate IDs beginning with 'example'.
#
# Supported wildcards are:
#  * (placeholder for any characters)
#  ? (placeholder for a single character)
[[principal]]
uid = 1001
certs = ["example*"]
```

In addition, all users added as principals must be in the `aziotcs` group.
