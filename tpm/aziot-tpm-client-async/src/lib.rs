// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_and_return,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::similar_names
)]

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

        let res: aziot_tpm_common_http::get_tpm_keys::Response = request(
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

        let _res: aziot_tpm_common_http::import_auth_key::Response = request(
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

        let res: aziot_tpm_common_http::sign_with_auth_key::Response = request(
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

async fn request<TRequest, TResponse>(
    client: &hyper::Client<http_common::Connector, hyper::Body>,
    method: http::Method,
    uri: &str,
    body: Option<&TRequest>,
) -> std::io::Result<TResponse>
where
    TRequest: serde::Serialize,
    TResponse: serde::de::DeserializeOwned,
{
    let req = hyper::Request::builder().method(method).uri(uri);
    // `req` is consumed by both branches, so this cannot be replaced with `Option::map_or_else`
    //
    // Ref: https://github.com/rust-lang/rust-clippy/issues/5822
    #[allow(clippy::option_if_let_else)]
    let req = if let Some(body) = body {
        let body = serde_json::to_vec(body)
            .expect("serializing request body to JSON cannot fail")
            .into();
        req.header(hyper::header::CONTENT_TYPE, "application/json")
            .body(body)
    } else {
        req.body(Default::default())
    };
    let req = req.expect("cannot fail to create hyper request");

    let res = client
        .request(req)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let (
        http::response::Parts {
            status: res_status_code,
            headers,
            ..
        },
        body,
    ) = res.into_parts();

    let mut is_json = false;
    for (header_name, header_value) in headers {
        if header_name == Some(hyper::header::CONTENT_TYPE) {
            let value = header_value
                .to_str()
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            if value == "application/json" {
                is_json = true;
            }
        }
    }

    if !is_json {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "malformed HTTP response",
        ));
    }

    let body = hyper::body::to_bytes(body)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let res: TResponse = match res_status_code {
        hyper::StatusCode::OK => {
            let res = serde_json::from_slice(&body)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            res
        }

        res_status_code
            if res_status_code.is_client_error() || res_status_code.is_server_error() =>
        {
            let res: http_common::ErrorBody<'static> = serde_json::from_slice(&body)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            return Err(std::io::Error::new(std::io::ErrorKind::Other, res.message));
        }

        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "malformed HTTP response",
            ))
        }
    };
    Ok(res)
}
