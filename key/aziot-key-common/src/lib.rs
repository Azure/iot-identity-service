// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct KeyHandle(pub String);

#[derive(Clone, Debug)]
pub enum CreateKeyValue {
    Generate { length: usize },
    Import { bytes: Vec<u8> },
}

#[derive(Clone, Copy, Debug)]
pub enum SignMechanism {
    // ECDSA keys
    Ecdsa,

    // Symmetric keys
    HmacSha256,
}

#[derive(Clone, Debug)]
pub enum EncryptMechanism {
    /// AEAD mechanism, like AES-256-GCM.
    Aead { iv: Vec<u8>, aad: Vec<u8> },

    /// RSA with PKCS1 padding.
    RsaPkcs1,

    /// RSA with no padding. Padding will have been performed by the caller.
    RsaNoPadding,
}
