// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

#[derive(Debug)]
pub struct Client {
    api_version: aziot_identity_common_http::ApiVersion,
    inner: hyper::Client<http_common::Connector, hyper::Body>,
}

impl Client {
    pub fn new(
        api_version: aziot_identity_common_http::ApiVersion,
        connector: http_common::Connector,
    ) -> Self {
        let inner = hyper::Client::builder().build(connector);
        Client { api_version, inner }
    }

    pub async fn reprovision(&self) -> Result<(), std::io::Error> {
        let body = aziot_identity_common_http::reprovision_device::Request {
            id_type: "aziot".to_owned(),
        };

        http_common::request_no_content(
            &self.inner,
            http::Method::POST,
            &format!(
                "http://foo/identities/device/reprovision?api-version={}",
                self.api_version
            ),
            Some(&body),
        )
        .await?;

        Ok(())
    }
}
