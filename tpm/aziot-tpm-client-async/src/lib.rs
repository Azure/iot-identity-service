// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

#[derive(Debug)]
pub struct Client {
    api_version: aziot_tpm_common_http::ApiVersion,
    inner: hyper::Client<http_common::Connector, hyper::Body>,
}

impl Client {
    pub fn new(
        api_version: aziot_tpm_common_http::ApiVersion,
        connector: http_common::Connector,
    ) -> Self {
        let inner = hyper::Client::builder().build(connector);
        Client { api_version, inner }
    }

    pub async fn get_tpm_keys(&self) -> std::io::Result<aziot_tpm_common::TpmKeys> {
        let body = aziot_tpm_common_http::get_tpm_keys::Request {};

        let res: aziot_tpm_common_http::get_tpm_keys::Response = http_common::request(
            &self.inner,
            http::Method::GET,
            &format!("http://foo/get_tpm_keys?api-version={}", self.api_version),
            Some(&body),
        )
        .await?;
        Ok(aziot_tpm_common::TpmKeys {
            endorsement_key: res.endorsement_key.0,
            storage_root_key: res.storage_root_key.0,
        })
    }

    pub async fn import_auth_key(&self, key: impl AsRef<[u8]>) -> std::io::Result<()> {
        let body = aziot_tpm_common_http::import_auth_key::Request {
            key: http_common::ByteString(key.as_ref().to_vec()),
        };

        let _res: aziot_tpm_common_http::import_auth_key::Response = http_common::request(
            &self.inner,
            http::Method::POST,
            &format!(
                "http://foo/import_auth_key?api-version={}",
                self.api_version
            ),
            Some(&body),
        )
        .await?;
        Ok(())
    }

    /// Returns the `data` digest
    pub async fn sign_with_auth_key(&self, data: impl AsRef<[u8]>) -> std::io::Result<Vec<u8>> {
        let body = aziot_tpm_common_http::sign_with_auth_key::Request {
            data: http_common::ByteString(data.as_ref().to_vec()),
        };

        let res: aziot_tpm_common_http::sign_with_auth_key::Response = http_common::request(
            &self.inner,
            http::Method::POST,
            &format!(
                "http://foo/sign_with_auth_key?api-version={}",
                self.api_version
            ),
            Some(&body),
        )
        .await?;
        Ok(res.digest.0)
    }
}
