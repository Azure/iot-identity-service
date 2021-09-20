// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::let_unit_value,
    clippy::missing_errors_doc,
    clippy::must_use_candidate
)]

#[derive(Debug)]
pub struct Client {
    api_version: aziot_cert_common_http::ApiVersion,
    inner: hyper::Client<http_common::Connector, hyper::Body>,
}

impl Client {
    pub fn new(
        api_version: aziot_cert_common_http::ApiVersion,
        connector: http_common::Connector,
    ) -> Self {
        let inner = connector.into_client();
        Client { api_version, inner }
    }

    pub async fn create_cert(
        &self,
        id: &str,
        csr: &[u8],
        issuer: Option<(&str, &aziot_key_common::KeyHandle)>,
    ) -> Result<Vec<u8>, std::io::Error> {
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

        let res: aziot_cert_common_http::get_cert::Response = http_common::request(
            &self.inner,
            http::Method::POST,
            &format!(
                "http://certd.sock/certificates?api-version={}",
                self.api_version
            ),
            Some(&body),
        )
        .await?;
        Ok(res.pem.0)
    }

    pub async fn import_cert(&self, id: &str, pem: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let body = aziot_cert_common_http::import_cert::Request {
            pem: aziot_cert_common_http::Pem(pem.to_owned()),
        };

        let res: aziot_cert_common_http::import_cert::Response = http_common::request(
            &self.inner,
            http::Method::PUT,
            &format!(
                "http://certd.sock/certificates/{}?api-version={}",
                percent_encoding::percent_encode(
                    id.as_bytes(),
                    http_common::PATH_SEGMENT_ENCODE_SET
                ),
                self.api_version,
            ),
            Some(&body),
        )
        .await?;
        Ok(res.pem.0)
    }

    pub async fn get_cert(&self, id: &str) -> Result<Vec<u8>, std::io::Error> {
        let res: aziot_cert_common_http::get_cert::Response = http_common::request::<(), _>(
            &self.inner,
            http::Method::GET,
            &format!(
                "http://certd.sock/certificates/{}?api-version={}",
                percent_encoding::percent_encode(
                    id.as_bytes(),
                    http_common::PATH_SEGMENT_ENCODE_SET
                ),
                self.api_version,
            ),
            None,
        )
        .await?;
        Ok(res.pem.0)
    }

    pub async fn delete_cert(&self, id: &str) -> Result<(), std::io::Error> {
        let () = http_common::request_no_content::<()>(
            &self.inner,
            http::Method::DELETE,
            &format!(
                "http://certd.sock/certificates/{}?api-version={}",
                percent_encoding::percent_encode(
                    id.as_bytes(),
                    http_common::PATH_SEGMENT_ENCODE_SET
                ),
                self.api_version,
            ),
            None,
        )
        .await?;
        Ok(())
    }
}
