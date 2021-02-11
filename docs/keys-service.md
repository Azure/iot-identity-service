# Keys Service

## API

An OpenAPI v3 spec for this service can be found at `/key/aziot-keyd/openapi/2020-09-01.yaml`

### Generate New Symmetric Key

`POST /key?api-version=2020-09-01`

#### Authentication

Required. See [API authentication](#api-authentication).

#### Request

```json
{
    "keyId": "...",
    "usage": "..."
}
```

`usage` is a comma-separated sequence of one or more of the following strings:

- `derive`
- `encrypt`
- `sign`

Eg: `"usage": "derive,sign"`

#### Response

```json
{
    "keyHandle": "string"
}
```

---

### Import Symmetric Key

`POST /key?api-version=2020-09-01`

#### Authentication

Required. See [API authentication](#api-authentication).

#### Request

```json
{
    "keyId": "...",
    "keyBytes": "base64-encoded-string"
}
```

#### Response

```json
{
    "keyHandle": "string"
}
```

---

### Get Existing Symmetric Key

`GET /key/{keyId}?api-version=2020-09-01`

#### Authentication

Required. See [API authentication](#api-authentication).

#### Response

```json
{
    "keyHandle": "string"
}
```

---

### Generate New Asymmetric Key Pair

`POST /keypair?api-version=2020-09-01`

#### Authentication

Required. See [API authentication](#api-authentication).

#### Request

```json
{
    "keyId": "string",
    "preferredAlgorithms": "..."
}
```

- `preferredAlgorithms` dictates the caller's preference for the key algorithm. It is a string with components separated by COLON U+003A `:`, where each component specifies the name of an algorithm and will be attempted by the KS in that order. The valid components are `"ec-p256"` for secp256r1, `"rsa-2048"` for 2048-bit RSA, `"rsa-4096"` for 4096-bit RSA, and `"*"` which indicates any algorithm of the KS's choice. For example, the caller might use `"ec-p256:rsa-2048:*"` to indicate that it would like the KS to use secp256r1, else RSA-2048 if that fails, else any other algorithm of the KS's choice if that also fails.

    If the KS does not recognize a particular component as an algorithm, or is unable to use the algorithm to generate a key pair, it should ignore that component and try the next one. If no components are left, the KS will return an error. It is allowed for the KS to unable to generate a key pair even if the wildcard algorithm is specified.

    If `preferredAlgorithms` is not specified, it will be interpreted the same as if it was `"*"`.

#### Response

```json
{
    "keyHandle": "string"
}
```

---

### Get Existing Asymmetric Key Pair

`GET /keypair/{keyPairId}?api-version=2020-09-01`

#### Authentication

Required. See [API authentication](#api-authentication).

#### Response

```json
{
    "keyHandle": "string"
}
```

---

### Get Parameter of Asymmetric Key Pair

`POST /parameters/{parameterName}?api-version=2020-09-01`

#### Authentication

Not required.

#### Request

```json
{
    "keyHandle": "string"
}
```

#### Response

```json
{
    "value": ...
}
```

The value of `value` in the response depends on the `parameterName`:

- `algorithm`: string, one of "ECDSA" and "RSA".

- `ec-curve-oid`: base64-encoded string containing the OID of the key's curve, in DER encoding. Only valid for ECDSA keys.

- `ec-point`: base64-encoded string containing the key's point. Only valid for ECDSA keys.

- `rsa-modulus`: base64-encoded string containing the key's modulus. Only valid for RSA keys.

- `rsa-exponent`: base64-encoded string containing the key's exponent as a big-endian bignumber. Only valid for RSA keys.

---

### Sign

`POST /sign?api-version=2020-09-01`

This includes both digital signatures using asymmetric keys and HMAC-SHA256 using symmetric keys.

#### Authentication

Not required.

#### Request

##### ECDSA

Only valid for ECDSA keys.

Note that the request takes the message digest, ie it must be calculated by the client.

```json
{
    "keyHandle": "string",
    "algorithm": "ECDSA",
    "parameters": {
        "digest": "base64-encoded-string",
    }
}
```

##### HMAC-SHA256

Only valid for symmetric keys.

```json
{
    "keyHandle": "string",
    "algorithm": "HMAC-SHA256",
    "parameters": {
        "message": "base64-encoded-string"
    }
}
```

#### Response

```json
{
    "signature": "base64-encoded-string"
}
```
---

### Encrypt

`POST /encrypt?api-version=2020-09-01`

#### Request

##### AEAD

Only valid for symmetric keys.

```json
{
    "keyHandle": "string",
    "algorithm": "AEAD",
    "parameters": {
        "iv": "base64-encoded-string",
        "aad": "base64-encoded-string"
    },
    "plaintext": "base64-encoded-string"
}
```

##### RSA-PKCS1

```json
{
    "keyHandle": "string",
    "algorithm": "RSA-PKCS1",
    "plaintext": "base64-encoded-string"
}
```

##### RSA-NO-PADDING

```json
{
    "keyHandle": "string",
    "algorithm": "RSA-NO-PADDING",
    "plaintext": "base64-encoded-string"
}
```

#### Response

```json
{
    "ciphertext": "base64-encoded-string"
}
```

For AEAD encryption, the ciphertext includes the AEAD tag so the caller does not need to handle that specially.

Note also that the exact AEAD algorithm used cannot be chosed by the caller; it is up to the libaziot-keys implementation. The libaziot-keys shipped by Microsoft uses AES-GCM. It also encodes a version number in the ciphertext to identify the algorithm used, so that the algorithm can be modified in the future if necessary while still being able to decrypt ciphertext created with the old algorithm.

---

### Decrypt

`POST /decrypt?api-version=2020-09-01`

#### Authentication

Not required.

#### Request

##### AEAD

Only valid for symmetric keys.

```json
{
    "keyHandle": "string",
    "algorithm": "AEAD",
    "parameters": {
        "iv": "base64-encoded-string",
        "aad": "base64-encoded-string"
    },
    "ciphertext": "base64-encoded-string"
}
```

##### RSA-PKCS1

```json
{
    "keyHandle": "string",
    "algorithm": "RSA-PKCS1",
    "ciphertext": "base64-encoded-string"
}
```

##### RSA-NO-PADDING

```json
{
    "keyHandle": "string",
    "algorithm": "RSA-NO-PADDING",
    "ciphertext": "base64-encoded-string"
}
```

#### Response

```json
{
    "plaintext": "base64-encoded-string"
}
```

The ciphertext must have come from the `/encrypt` API so that it matches the format that the `/decrypt` API expects. See the note in the `/encrypt` API above for details.

---

## API authentication

APIs that create or retrieve keys require the caller to authenticate with KS. Allowed callers are listed in the KS config directory, `/etc/aziot/keyd/config.d`.

Each file in the KS config directory should list allowed Unix user IDs (UIDs) and the keys that those users may access. The file name does not matter, but files must have the extension `.toml`. Only files directly under the config directory are parsed (i.e. the config directory is not searched recursively).

For example, `/etc/aziot/keyd/config.d/example.toml`:
```toml
# Each user should be listed as a [[principal]]
# This principal grants user 1000 access to the 'example1' and 'example2' key.
[[principal]]
uid = 1000
keys = ["example1", "example2"]

# Wildcards may also be used for key IDs.
# This principal grants user 1001 access to all key IDs beginning with 'example'.
#
# Supported wildcards are:
#  * (placeholder for any characters)
#  ? (placeholder for a single character)
[[principal]]
uid = 1001
keys = ["example*"]
```

In addition, all users added as principals must be in the `aziotks` group.

## Code organization

The KS is made up of the following crates:

- aziot-keyd

    This is the main KS crate. It implements the HTTP server and REST API.

- aziot-keys

    libaziot-keys is a dynamic library that implements key storage and crypto operations. The REST API exported by KS maps nearly one-to-one with the C API exposed by libaziot-keys.

    It exists as a dynamic library so that users can replace it with their own alternative implementation that provides the same interface. It is similar to the libiothsm library that was used by iotedged in IoT Edge 1.1 and earlier, except that it only concerns itself with keys (both symmetric and asymmetric), not certificates. Also, unlike libiothsm, libaziot-keys does not require keys to be exportable to memory.

    The implementation of libaziot-keys shipped by Microsoft supports keys that are stored on the filesystem and manipulated in memory, and keys that are accessed via PKCS#11.

- aziot-key-client and aziot-key-client-async

    These crate contain clients for the KS API.

- aziot-key-common

    This crate contains common types used by the aziot-key-client and aziot-keyd crates.

- aziot-key-common-http

    This crate contains common types used by the aziot-key-client and aziot-keyd crates related to the HTTP request and response types of the API requests.

- aziot-key-openssl-engine

    This is an openssl engine that wraps a client from aziot-key-client and implements the openssl engine and key API in terms of that client. For example, signing with an EC key is implemented by invoking the KS's `/sign` REST API.

- aziot-key-openssl-engine-shared

    This is a re-export of aziot-key-openssl-engine that is compiled as a shared object (`.so`). It is not used by the services in this repository; rather it is intended for third-party applications like user modules that use openssl for TLS.
