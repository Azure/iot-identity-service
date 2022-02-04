// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::missing_errors_doc, clippy::must_use_candidate)]

use http_common::{ErrorBody, HttpRequest};

#[derive(Debug)]
pub struct Client {
    api_version: aziot_tpm_common_http::ApiVersion,
    connector: http_common::Connector,
}

impl Client {
    pub fn new(
        api_version: aziot_tpm_common_http::ApiVersion,
        connector: http_common::Connector,
    ) -> Self {
        Client {
            api_version,
            connector,
        }
    }

    pub async fn get_tpm_keys(&self) -> std::io::Result<aziot_tpm_common::TpmKeys> {
        let uri = format!(
            "http://tpmd.sock/get_tpm_keys?api-version={}",
            self.api_version
        );

        let request: HttpRequest<(), _> = HttpRequest::get(self.connector.clone(), &uri);

        let response = request.json_response().await?;
        let response: aziot_tpm_common_http::get_tpm_keys::Response =
            response.parse_expect_ok::<_, ErrorBody<'_>>()?;

        Ok(aziot_tpm_common::TpmKeys {
            endorsement_key: response.endorsement_key.0,
            storage_root_key: response.storage_root_key.0,
        })
    }

    pub async fn import_auth_key(&self, key: impl AsRef<[u8]>) -> std::io::Result<()> {
        let uri = format!(
            "http://tpmd.sock/import_auth_key?api-version={}",
            self.api_version
        );

        let body = aziot_tpm_common_http::import_auth_key::Request {
            key: http_common::ByteString(key.as_ref().to_vec()),
        };

        let request = HttpRequest::post(self.connector.clone(), &uri, Some(body));

        let response = request.json_response().await?;
        let _response: aziot_tpm_common_http::import_auth_key::Response =
            response.parse_expect_ok::<_, ErrorBody<'_>>()?;

        Ok(())
    }

    /// Returns the `data` digest
    pub async fn sign_with_auth_key(&self, data: impl AsRef<[u8]>) -> std::io::Result<Vec<u8>> {
        let uri = format!(
            "http://tpmd.sock/sign_with_auth_key?api-version={}",
            self.api_version
        );

        let body = aziot_tpm_common_http::sign_with_auth_key::Request {
            data: http_common::ByteString(data.as_ref().to_vec()),
        };

        let request = HttpRequest::post(self.connector.clone(), &uri, Some(body));

        let response = request.json_response().await?;
        let response: aziot_tpm_common_http::sign_with_auth_key::Response =
            response.parse_expect_ok::<_, ErrorBody<'_>>()?;

        Ok(response.digest.0)
    }
}
