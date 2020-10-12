# API

Note: For both requests and responses, the PEM string can contain multiple certificates. This happens when the certificates form a chain where the first cert is the leaf cert.

## Create New Certificate from CSR

`POST /certificates`

### Request

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

### Response

```json
{
    "pem": "string"
}
```

---

## Import Certificate

`PUT /certificates/{certId}`

### Request

```json
{
    "pem": "string"
}
```

### Response

```json
{
    "pem": "string"
}
```

---

## Get Existing Certificate

`GET /certificates/{certId}`

### Response

```json
{
    "pem": "string"
}
```

---

## Delete Existing Certificate

`DELETE /certificates/{certId}`

### Response

HTTP 204 No Content

---
