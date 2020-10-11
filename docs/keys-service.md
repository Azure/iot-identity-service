# API

## Generate New Symmetric Key

`POST /key`

### Request

```json
{
    "keyId": "...",
    "lengthBytes": 32
}
```

### Response

```json
{
    "keyHandle": "string"
}
```

---

## Import Symmetric Key

`POST /key`

### Request

```json
{
    "keyId": "...",
    "keyBytes": "base64-encoded-string"
}
```

### Response

```json
{
    "keyHandle": "string"
}
```

---

## Get Existing Symmetric Key

`GET /key/{keyId}`

### Response

```json
{
    "keyHandle": "string"
}
```

---

## Generate New Asymmetric Key Pair

`POST /keypair`

### Request

```json
{
    "keyId": "string",
    "preferredAlgorithms": "..."
}
```

- `preferredAlgorithms` dictates the caller's preference for the key algorithm. It is a string with components separated by COLON U+003A `:`, where each component specifies the name of an algorithm and will be attempted by the KS in that order. The valid components are `"ec-p256"` for secp256r1, `"rsa-2048"` for 2048-bit RSA, `"rsa-4096"` for 4096-bit RSA, and `"*"` which indicates any algorithm of the KS's choice. For example, the caller might use `"ec-p256:rsa-2048:*"` to indicate that it would like the KS to use secp256r1, else RSA-2048 if that fails, else any other algorithm of the KS's choice if that also fails.

    If the KS does not recognize a particular component as an algorithm, or is unable to use the algorithm to generate a key pair, it should ignore that component and try the next one. If no components are left, the KS will return an error. It is allowed for the KS to unable to generate a key pair even if the wildcard algorithm is specified.

    If `preferredAlgorithms` is not specified, it will be interpreted the same as if it was `"*"`.

### Response

```json
{
    "keyHandle": "string"
}
```

---

## Get Existing Asymmetric Key Pair

`GET /keypair/{keyPairId}`

### Response

```json
{
    "keyHandle": "string"
}
```

---

## Get Parameter of Asymmetric Key Pair

`POST /parameters/{parameterName}`

### Request

```json
{
    "keyHandle": "string"
}
```

### Response

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

## Sign

`POST /sign`

This includes both digital signatures using asymmetric keys and HMAC-SHA256 using symmetric keys.

### Request

#### ECDSA

Only valid for ECDSA keys.

Note that the request takes the message digest, ie it must be calculated by the client.

```json
{
    "keyHandle": "string",
    "parameters": {
        "algorithm": "ECDSA",    
        "digest": "base64-encoded-string",
    }
}
```

#### HMAC-SHA256

```json
{
    "keyHandle": "string",
    "parameters": {
        "algorithm": "HMAC-SHA256",
        "message": "base64-encoded-string"
    }
}
```

### Response

```json
{
    "signature": "base64-encoded-string"
}
```
---

## Encrypt

`POST /encrypt`

### Request

#### AEAD

Only valid for symmetric keys.

```json
{
    "keyHandle": "string",
    "parameters": {
        "algorithm": "AEAD",
        "iv": "base64-encoded-string",
        "aad": "base64-encoded-string"
    },
    "plaintext": "base64-encoded-string"
}
```

#### RSA-PKCS1

```json
{
    "keyHandle": "string",
    "parameters": {
        "algorithm": "RSA-PKCS1",
    },
    "plaintext": "base64-encoded-string"
}
```

#### RSA-NO-PADDING

```json
{
    "keyHandle": "string",
    "parameters": {
        "algorithm": "RSA-NO-PADDING",
    },
    "plaintext": "base64-encoded-string"
}
```

### Response

```json
{
    "ciphertext": "base64-encoded-string"
}
```

The ciphertext includes the AEAD tag so the caller does not need to handle that specially.

The default implementation uses AES-256-GCM, but this is not controllable by the caller. The ciphertext also includes a version number to identify the algorithm used (AES-256-GCM). This allows for the implementation to select a different algorithm in the future and still be able to decrypt ciphertexts encrypted by the old algorithm.

---

## Decrypt

`POST /decrypt`

### Request

#### AEAD

Only valid for symmetric keys.

```json
{
    "keyHandle": "string",
    "parameters": {
        "algorithm": "AEAD",
        "iv": "base64-encoded-string",
        "aad": "base64-encoded-string"
    },
    "ciphertext": "base64-encoded-string"
}
```

#### RSA-PKCS1

```json
{
    "keyHandle": "string",
    "parameters": {
        "algorithm": "RSA-PKCS1",
    },
    "ciphertext": "base64-encoded-string"
}
```

#### RSA-NO-PADDING

```json
{
    "keyHandle": "string",
    "parameters": {
        "algorithm": "RSA-NO-PADDING",
    },
    "ciphertext": "base64-encoded-string"
}
```

### Response

```json
{
    "plaintext": "base64-encoded-string"
}
```

The ciphertext must have come from the `/encrypt` API so that it matches the format that the `/decrypt` API expects. See the note in the `/encrypt` API above for details.

---

# Code organization

The KS is made up of the following crates:

- ksd

    This is the main KS crate. It implements the HTTP server and REST API.

- iothsm-keygen

    libiothsm-keygen is a dynamic library that implements key storage and crypto operations. The REST API exported by KS maps nearly one-to-one with the C API exposed by libiothsm-keygen.

    It exists as a dynamic library so that users can replace it with their own alternative implementation that provides the same interface. It is similar to the existing libiothsm that is used by iotedged, except that it only concerns itself with keys, not certificates.

    Our implementation of libiothsm-keygen supports keys that are stored on the filesystem and manipulated in memory, and keys that are accessed via PKCS#11.

- aziot-key-client

    This crate contains clients for the KS API.

- aziot-key-common

    This crate contains common types used by the aziot-key-client and ksd crates.

- aziot-key-common-http

    This crate contains common types used by the aziot-key-client and ksd crates related to the HTTP request and response types of the API requests.

- aziot-key-openssl-engine

    This is an openssl engine that wraps a client from aziot-key-client and implements the openssl engine and key API in terms of that client. For example, signing with an EC key is implemented by invoking the KS's `/sign` REST API.
