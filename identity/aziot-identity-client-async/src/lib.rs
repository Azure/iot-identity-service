// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

#[derive(Debug)]
pub struct Client {
    api_version: aziot_identity_common_http::ApiVersion,
    inner: hyper::Client<http_common::Connector, hyper::Body>,
    max_retries: u32,
}

impl Client {
    pub fn new(
        api_version: aziot_identity_common_http::ApiVersion,
        connector: http_common::Connector,
        max_retries: u32,
    ) -> Self {
        let inner = hyper::Client::builder().build(connector);
        Client {
            api_version,
            inner,
            max_retries,
        }
    }

    pub async fn reprovision(&self) -> Result<(), std::io::Error> {
        let body = aziot_identity_common_http::reprovision_device::Request {
            id_type: "aziot".to_owned(),
        };

        http_common::request_no_content_with_retry(
            &self.inner,
            http::Method::POST,
            &format!(
                "http://identityd.sock/identities/device/reprovision?api-version={}",
                self.api_version
            ),
            Some(&body),
            self.max_retries,
        )
        .await?;

        Ok(())
    }
}
