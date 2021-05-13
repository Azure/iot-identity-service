// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

#[derive(Debug)]
pub struct Client {
    api_version: aziot_key_common_http::ApiVersion,
    inner: hyper::Client<http_common::Connector, hyper::Body>,
}

impl Client {
    pub fn new(
        api_version: aziot_key_common_http::ApiVersion,
        connector: http_common::Connector,
    ) -> Self {
        let inner = hyper::Client::builder().build(connector);
        Client { api_version, inner }
    }

    pub async fn create_key_pair_if_not_exists(
        &self,
        id: &str,
        preferred_algorithms: Option<&str>,
    ) -> std::io::Result<aziot_key_common::KeyHandle> {
        let body = aziot_key_common_http::create_key_pair_if_not_exists::Request {
            id: id.to_owned(),
            preferred_algorithms: preferred_algorithms.map(ToOwned::to_owned),
        };

        let res: aziot_key_common_http::create_key_pair_if_not_exists::Response =
            http_common::request(
                &self.inner,
                http::Method::POST,
                &format!("http://keyd.sock/keypair?api-version={}", self.api_version),
                Some(&body),
            )
            .await?;
        Ok(res.handle)
    }

    pub async fn load_key_pair(&self, id: &str) -> std::io::Result<aziot_key_common::KeyHandle> {
        let res: aziot_key_common_http::load::Response = http_common::request::<(), _>(
            &self.inner,
            http::Method::GET,
            &format!(
                "http://keyd.sock/keypair/{}?api-version={}",
                percent_encoding::percent_encode(
                    id.as_bytes(),
                    http_common::PATH_SEGMENT_ENCODE_SET
                ),
                self.api_version,
            ),
            None,
        )
        .await?;
        Ok(res.handle)
    }

    pub async fn get_key_pair_public_parameter(
        &self,
        handle: &aziot_key_common::KeyHandle,
        parameter_name: &str,
    ) -> std::io::Result<String> {
        let body = aziot_key_common_http::get_key_pair_public_parameter::Request {
            key_handle: handle.clone(),
        };

        let res: aziot_key_common_http::get_key_pair_public_parameter::Response =
            http_common::request(
                &self.inner,
                http::Method::POST,
                &format!(
                    "http://keyd.sock/parameters/{}?api-version={}",
                    percent_encoding::percent_encode(
                        parameter_name.as_bytes(),
                        http_common::PATH_SEGMENT_ENCODE_SET
                    ),
                    self.api_version,
                ),
                Some(&body),
            )
            .await?;
        Ok(res.value)
    }

    pub async fn delete_key_pair(
        &self,
        key_handle: &aziot_key_common::KeyHandle,
    ) -> std::io::Result<()> {
        let body = aziot_key_common_http::delete::Request {
            key_handle: key_handle.clone(),
        };

        http_common::request_no_content(
            &self.inner,
            http::Method::GET,
            &format!("http://keyd.sock/keypair?api-version={}", self.api_version),
            Some(&body),
        )
        .await?;
        Ok(())
    }

    pub async fn create_key_if_not_exists(
        &self,
        id: &str,
        value: aziot_key_common::CreateKeyValue,
        usage: &[aziot_key_common::KeyUsage],
    ) -> std::io::Result<aziot_key_common::KeyHandle> {
        let body = match value {
            aziot_key_common::CreateKeyValue::Generate => {
                aziot_key_common_http::create_key_if_not_exists::Request {
                    id: id.to_owned(),
                    import_key_bytes: None,
                    usage: usage.to_owned(),
                }
            }
            aziot_key_common::CreateKeyValue::Import { bytes } => {
                aziot_key_common_http::create_key_if_not_exists::Request {
                    id: id.to_owned(),
                    import_key_bytes: Some(http_common::ByteString(bytes)),
                    usage: usage.to_owned(),
                }
            }
        };

        let res: aziot_key_common_http::create_key_if_not_exists::Response = http_common::request(
            &self.inner,
            http::Method::POST,
            &format!("http://keyd.sock/key?api-version={}", self.api_version),
            Some(&body),
        )
        .await?;
        Ok(res.handle)
    }

    pub async fn load_key(&self, id: &str) -> std::io::Result<aziot_key_common::KeyHandle> {
        let res: aziot_key_common_http::load::Response = http_common::request::<(), _>(
            &self.inner,
            http::Method::GET,
            &format!(
                "http://keyd.sock/key/{}?api-version={}",
                percent_encoding::percent_encode(
                    id.as_bytes(),
                    http_common::PATH_SEGMENT_ENCODE_SET
                ),
                self.api_version,
            ),
            None,
        )
        .await?;
        Ok(res.handle)
    }

    pub async fn delete_key(
        &self,
        key_handle: &aziot_key_common::KeyHandle,
    ) -> std::io::Result<()> {
        let body = aziot_key_common_http::delete::Request {
            key_handle: key_handle.clone(),
        };

        http_common::request_no_content(
            &self.inner,
            http::Method::GET,
            &format!("http://keyd.sock/key?api-version={}", self.api_version),
            Some(&body),
        )
        .await?;
        Ok(())
    }

    pub async fn create_derived_key(
        &self,
        base_handle: &aziot_key_common::KeyHandle,
        derivation_data: &[u8],
    ) -> std::io::Result<aziot_key_common::KeyHandle> {
        let body = aziot_key_common_http::create_derived_key::Request {
            base_handle: base_handle.clone(),
            derivation_data: http_common::ByteString(derivation_data.to_owned()),
        };

        let res: aziot_key_common_http::create_derived_key::Response = http_common::request(
            &self.inner,
            http::Method::POST,
            &format!(
                "http://keyd.sock/derivedkey?api-version={}",
                self.api_version
            ),
            Some(&body),
        )
        .await?;
        Ok(res.handle)
    }

    pub async fn export_derived_key(
        &self,
        handle: &aziot_key_common::KeyHandle,
    ) -> std::io::Result<Vec<u8>> {
        let body = aziot_key_common_http::export_derived_key::Request {
            handle: handle.clone(),
        };

        let res: aziot_key_common_http::export_derived_key::Response = http_common::request(
            &self.inner,
            http::Method::POST,
            &format!(
                "http://keyd.sock/derivedkey/export?api-version={}",
                self.api_version
            ),
            Some(&body),
        )
        .await?;
        Ok(res.key.0)
    }

    pub async fn sign(
        &self,
        handle: &aziot_key_common::KeyHandle,
        mechanism: aziot_key_common::SignMechanism,
        digest: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let body = aziot_key_common_http::sign::Request {
            key_handle: handle.clone(),
            parameters: match mechanism {
                aziot_key_common::SignMechanism::Ecdsa => {
                    aziot_key_common_http::sign::Parameters::Ecdsa {
                        digest: http_common::ByteString(digest.to_owned()),
                    }
                }

                aziot_key_common::SignMechanism::HmacSha256 => {
                    aziot_key_common_http::sign::Parameters::HmacSha256 {
                        message: http_common::ByteString(digest.to_owned()),
                    }
                }
            },
        };

        let res: aziot_key_common_http::sign::Response = http_common::request(
            &self.inner,
            http::Method::POST,
            &format!("http://keyd.sock/sign?api-version={}", self.api_version),
            Some(&body),
        )
        .await?;
        let signature = res.signature.0;
        Ok(signature)
    }

    pub async fn encrypt(
        &self,
        handle: &aziot_key_common::KeyHandle,
        mechanism: aziot_key_common::EncryptMechanism,
        plaintext: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let body = aziot_key_common_http::encrypt::Request {
            key_handle: handle.clone(),
            parameters: match mechanism {
                aziot_key_common::EncryptMechanism::Aead { iv, aad } => {
                    aziot_key_common_http::encrypt::Parameters::Aead {
                        iv: http_common::ByteString(iv),
                        aad: http_common::ByteString(aad),
                    }
                }

                aziot_key_common::EncryptMechanism::RsaPkcs1 => {
                    aziot_key_common_http::encrypt::Parameters::RsaPkcs1
                }

                aziot_key_common::EncryptMechanism::RsaNoPadding => {
                    aziot_key_common_http::encrypt::Parameters::RsaNoPadding
                }
            },
            plaintext: http_common::ByteString(plaintext.to_owned()),
        };

        let res: aziot_key_common_http::encrypt::Response = http_common::request(
            &self.inner,
            http::Method::POST,
            &format!("http://keyd.sock/encrypt?api-version={}", self.api_version),
            Some(&body),
        )
        .await?;
        let ciphertext = res.ciphertext.0;
        Ok(ciphertext)
    }

    pub async fn decrypt(
        &self,
        handle: &aziot_key_common::KeyHandle,
        mechanism: aziot_key_common::EncryptMechanism,
        ciphertext: &[u8],
    ) -> std::io::Result<Vec<u8>> {
        let body = aziot_key_common_http::decrypt::Request {
            key_handle: handle.clone(),
            parameters: match mechanism {
                aziot_key_common::EncryptMechanism::Aead { iv, aad } => {
                    aziot_key_common_http::encrypt::Parameters::Aead {
                        iv: http_common::ByteString(iv),
                        aad: http_common::ByteString(aad),
                    }
                }

                aziot_key_common::EncryptMechanism::RsaPkcs1 => {
                    aziot_key_common_http::encrypt::Parameters::RsaPkcs1
                }

                aziot_key_common::EncryptMechanism::RsaNoPadding => {
                    aziot_key_common_http::encrypt::Parameters::RsaNoPadding
                }
            },
            ciphertext: http_common::ByteString(ciphertext.to_owned()),
        };

        let res: aziot_key_common_http::decrypt::Response = http_common::request(
            &self.inner,
            http::Method::POST,
            &format!("http://keyd.sock/decrypt?api-version={}", self.api_version),
            Some(&body),
        )
        .await?;
        let plaintext = res.plaintext.0;
        Ok(plaintext)
    }
}
