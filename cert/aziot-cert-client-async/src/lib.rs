// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_and_return,
    clippy::let_unit_value,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::similar_names
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
        let inner = hyper::Client::builder().build(connector);
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

        let res: aziot_cert_common_http::get_cert::Response = request(
            &self.inner,
            http::Method::POST,
            &format!("http://foo/certificates?api-version={}", self.api_version),
            Some(&body),
        )
        .await?;
        Ok(res.pem.0)
    }

    pub async fn import_cert(&self, id: &str, pem: &[u8]) -> Result<Vec<u8>, std::io::Error> {
        let body = aziot_cert_common_http::import_cert::Request {
            pem: aziot_cert_common_http::Pem(pem.to_owned()),
        };

        let res: aziot_cert_common_http::import_cert::Response = request(
            &self.inner,
            http::Method::PUT,
            &format!(
                "http://foo/certificates/{}?api-version={}",
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
        let res: aziot_cert_common_http::get_cert::Response = request::<(), _>(
            &self.inner,
            http::Method::GET,
            &format!(
                "http://foo/certificates/{}?api-version={}",
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
        let () = request_no_content::<()>(
            &self.inner,
            http::Method::DELETE,
            &format!(
                "http://foo/certificates/{}?api-version={}",
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
        hyper::StatusCode::OK | hyper::StatusCode::CREATED => {
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

async fn request_no_content<TRequest>(
    client: &hyper::Client<http_common::Connector, hyper::Body>,
    method: http::Method,
    uri: &str,
    body: Option<&TRequest>,
) -> std::io::Result<()>
where
    TRequest: serde::Serialize,
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

    let body = hyper::body::to_bytes(body)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    match res_status_code {
        hyper::StatusCode::NO_CONTENT => Ok(()),

        res_status_code
            if res_status_code.is_client_error() || res_status_code.is_server_error() =>
        {
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

            let res: http_common::ErrorBody<'static> = serde_json::from_slice(&body)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            Err(std::io::Error::new(std::io::ErrorKind::Other, res.message))
        }

        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "malformed HTTP response",
        )),
    }
}
