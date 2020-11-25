# API

The HTTP API mirrors the underlying `aziot-tpm-sys` API:

```c
// "GET /get_tpm_keys"
int aziot_tpm_get_keys(unsigned char** ek, size_t* ek_size, unsigned char** srk, size_t* srk_size);

// "POST /import_auth_key"
int aziot_tpm_import_auth_key(const unsigned char* key, size_t key_size);

// "POST /sign_with_auth_key"
int aziot_tpm_sign_with_auth_key(
    const unsigned char* data, size_t data_size,
    unsigned char** digest, size_t* digest_size);
```

## Get Endorsement Key and Storage Root Key

### Request

`GET /get_tpm_keys`

### Response

```json
{
    "endorsement_key": "<base64 encoded key>",
    "storage_root_key": "<base64 encoded key>",
}
```

## Activate Auth Key

Imports key that has been previously encrypted with the endorsement key and storage root key into the TPM key storage.

### Request

`POST /import_auth_key`

```json
{
    "key": "<base64 encoded key>",
}
```

### Response

## Sign With Auth Key

Hashes the data using the stored auth key (imported via `POST /import_auth_key`).

### Request

`POST /sign_with_auth_key`

```json
{
    "data": "<base64 encoded data>",
}
```

### Response

```json
{
    "digest": "<base64 encoded data>",
}
```

# Code organization

The TPMS is made up of the following crates:

- aziot-tpmd

    This is the main TPMS crate. It implements the HTTP server and REST API on-top of the aziot-tpm crate.

- aziot-tpm-sys

    Rust bindings to an in-tree C library that implements low level TPM operations. This crate is a strict subset of the existing `hsm-sys` crate + `azure-iot-hsm-c` libraries, with all non-TPM related functionality stripped out.

- aziot-tpm-rs

    Idiomatic Rust interface around aziot-tpm-sys, handling all low-level `unsafe` invariants required when calling into aziot-tpm-sys.

- aziot-tpm-client-async

    This crate contains the HTTP client for the TPMS API.

- aziot-tpm-common-http

    This crate contains common types used by the aziot-tpm-client and aziot-tpmd crates related to the HTTP request and response types of the API requests.
