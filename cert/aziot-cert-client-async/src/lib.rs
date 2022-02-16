// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::let_unit_value,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

use http_common::{ErrorBody, HttpRequest};

#[derive(Debug)]
pub struct Client {
    api_version: aziot_cert_common_http::ApiVersion,
    connector: http_common::Connector,
    max_retries: u32,
}

impl Client {
    pub fn new(
        api_version: aziot_cert_common_http::ApiVersion,
        connector: http_common::Connector,
        max_retries: u32,
    ) -> Self {
        Client {
            api_version,
            connector,
            max_retries,
        }
    }

    pub async fn create_cert(
        &self,
        id: &str,
        csr: &[u8],
        issuer: Option<(&str, &aziot_key_common::KeyHandle)>,
    ) -> Result<Vec<u8>, std::io::Error> {
        let uri = format!(
            "http://certd.sock/certificates?api-version={}",
            self.api_version
        );

        let body = aziot_cert_common_http::create_cert::Request {
            cert_id: id.to_owned(),
            csr: aziot_cert_common_http::Pem(csr.to_owned()),
            issuer: issuer.map(|(cert_id, private_key_handle)| {
                aziot_cert_common_http::create_cert::Issuer {
                    cert_id: cert_id.to_owned(),
                    private_key_handle: private_key_handle.clone(),
                }
            }),
        };

        let request = HttpRequest::post(self.connector.clone(), &uri, Some(body))
            .with_retry(self.max_retries);

        let response = request.json_response().await?;
        let response: aziot_cert_common_http::create_cert::Response =
            response.parse::<_, ErrorBody<'_>>(&[hyper::StatusCode::CREATED])?;

        Ok(response.pem.0)
    }

    pub async fn import_cert(&self, id: &str, pem: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let uri = format!(
            "http://certd.sock/certificates/{}?api-version={}",
            percent_encoding::percent_encode(id.as_bytes(), http_common::PATH_SEGMENT_ENCODE_SET),
            self.api_version,
        );

        let body = aziot_cert_common_http::import_cert::Request {
            pem: aziot_cert_common_http::Pem(pem.to_owned()),
        };

        let request =
            HttpRequest::put(self.connector.clone(), &uri, body).with_retry(self.max_retries);

        let response = request.json_response().await?;
        let response: aziot_cert_common_http::import_cert::Response =
            response.parse::<_, ErrorBody<'_>>(&[hyper::StatusCode::CREATED])?;

        Ok(response.pem.0)
    }

    pub async fn get_cert(&self, id: &str) -> Result<Vec<u8>, std::io::Error> {
        let uri = format!(
            "http://certd.sock/certificates/{}?api-version={}",
            percent_encoding::percent_encode(id.as_bytes(), http_common::PATH_SEGMENT_ENCODE_SET),
            self.api_version,
        );

        let request: HttpRequest<(), _> =
            HttpRequest::get(self.connector.clone(), &uri).with_retry(self.max_retries);

        let response = request.json_response().await?;
        let response: aziot_cert_common_http::get_cert::Response =
            response.parse_expect_ok::<_, ErrorBody<'_>>()?;

        Ok(response.pem.0)
    }

    pub async fn delete_cert(&self, id: &str) -> Result<(), std::io::Error> {
        let uri = format!(
            "http://certd.sock/certificates/{}?api-version={}",
            percent_encoding::percent_encode(id.as_bytes(), http_common::PATH_SEGMENT_ENCODE_SET),
            self.api_version,
        );

        let request: HttpRequest<(), _> =
            HttpRequest::delete(self.connector.clone(), &uri, None).with_retry(self.max_retries);

        request.no_content_response().await
    }
}
