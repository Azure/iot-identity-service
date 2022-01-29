// Copyright (c) Microsoft. All rights reserved.

use std::io::{Error, ErrorKind};

const CONTENT_TYPE_JSON: &str = "application/json";

pub struct HttpRequest<TBody, TConnector> {
    connector: TConnector,
    method: hyper::Method,
    uri: String,
    headers: http::HeaderMap<http::HeaderValue>,
    body: Option<TBody>,
    timeout: std::time::Duration,
    retries: u32,
}

impl<TBody, TConnector> HttpRequest<TBody, TConnector>
where
    TBody: serde::Serialize,
    TConnector: Clone + Send + Sync + hyper::client::connect::Connect + 'static,
{
    pub fn delete(connector: TConnector, uri: &str, body: Option<TBody>) -> Self {
        HttpRequest {
            connector,
            method: hyper::Method::DELETE,
            uri: uri.to_string(),
            headers: http::HeaderMap::default(),
            body,
            timeout: std::time::Duration::from_secs(30),
            retries: 0,
        }
    }

    pub fn get(connector: TConnector, uri: &str) -> Self {
        HttpRequest {
            connector,
            method: hyper::Method::GET,
            uri: uri.to_string(),
            headers: http::HeaderMap::default(),
            body: None,
            timeout: std::time::Duration::from_secs(30),
            retries: 0,
        }
    }

    pub fn post(connector: TConnector, uri: &str, body: Option<TBody>) -> Self {
        HttpRequest {
            connector,
            method: hyper::Method::POST,
            uri: uri.to_string(),
            headers: http::HeaderMap::default(),
            body,
            timeout: std::time::Duration::from_secs(30),
            retries: 0,
        }
    }

    pub fn put(connector: TConnector, uri: &str, body: TBody) -> Self {
        HttpRequest {
            connector,
            method: hyper::Method::PUT,
            uri: uri.to_string(),
            headers: http::HeaderMap::default(),
            body: Some(body),
            timeout: std::time::Duration::from_secs(30),
            retries: 0,
        }
    }

    pub fn with_retry(mut self, retries: u32) -> Self {
        self.retries = retries;

        self
    }

    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;

        self
    }

    pub fn add_header(
        &mut self,
        name: hyper::header::HeaderName,
        value: &str,
    ) -> Result<(), Error> {
        let value = http::HeaderValue::from_str(value)
            .map_err(|err| Error::new(ErrorKind::InvalidInput, err))?;

        self.headers.insert(name, value);

        Ok(())
    }

    pub async fn no_content_response(self) -> Result<(), Error> {
        let (response_status, _, _) = self.process_request(false).await?;

        if response_status == hyper::StatusCode::NO_CONTENT {
            Ok(())
        } else {
            Err(Error::new(ErrorKind::Other, "invalid HTTP status code"))
        }
    }

    pub async fn json_response(self) -> Result<HttpResponse, Error> {
        let (status, headers, body) = self.process_request(true).await?;

        let is_json_response = if let Some(content_type) = headers.get(hyper::header::CONTENT_TYPE)
        {
            let content_type = content_type
                .to_str()
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

            content_type.contains(CONTENT_TYPE_JSON)
        } else {
            false
        };

        if !is_json_response {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid Content-Type; expected JSON",
            ));
        }

        Ok(HttpResponse {
            status,
            body: body.expect("process_request did not return body"),
        })
    }

    async fn process_request(
        self,
        has_response: bool,
    ) -> Result<
        (
            hyper::StatusCode,
            http::HeaderMap<http::HeaderValue>,
            Option<hyper::body::Bytes>,
        ),
        Error,
    > {
        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().build(self.connector);

        let mut current_attempt = 1;
        let retry_limit = self.retries + 1;

        let response = loop {
            let mut request = hyper::Request::builder()
                .method(&self.method)
                .uri(&self.uri);

            let request_body = if let Some(body) = &self.body {
                request = request.header(hyper::header::CONTENT_TYPE, CONTENT_TYPE_JSON);

                serde_json::to_vec(body)
                    .expect("cannot fail to serialize request")
                    .into()
            } else {
                hyper::Body::default()
            };

            for (header_name, header_value) in &self.headers {
                request = request.header(header_name, header_value);
            }

            let request = request
                .body(request_body)
                .expect("cannot fail to create request");

            let err = match tokio::time::timeout(self.timeout, client.request(request)).await {
                Ok(response) => {
                    match response {
                        Ok(response) => break response,
                        Err(err) => {
                            if err.is_connect() {
                                // Network error.
                                std::io::Error::new(std::io::ErrorKind::NotConnected, err)
                            } else {
                                std::io::Error::new(std::io::ErrorKind::Other, err)
                            }
                        }
                    }
                }

                Err(timeout) => timeout.into(),
            };

            log::warn!(
                "Failed to send HTTP request (attempt {} of {}): {}",
                current_attempt,
                retry_limit,
                err
            );

            if current_attempt == retry_limit {
                return Err(err);
            }

            current_attempt += 1;

            // Wait a short time between failed requests.
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
        };

        let (
            http::response::Parts {
                status: response_status,
                headers: response_headers,
                ..
            },
            response_body,
        ) = response.into_parts();

        let response_body = if has_response {
            let response_body = hyper::body::to_bytes(response_body)
                .await
                .map_err(|err| Error::new(ErrorKind::Other, err))?;

            Some(response_body)
        } else {
            None
        };

        Ok((response_status, response_headers, response_body))
    }
}

pub struct HttpResponse {
    status: hyper::StatusCode,
    body: hyper::body::Bytes,
}

impl HttpResponse {
    pub fn into_parts(self) -> (hyper::StatusCode, hyper::body::Bytes) {
        (self.status, self.body)
    }

    pub fn parse_expect_ok<TResponse, TError>(self) -> Result<TResponse, Error>
    where
        TResponse: serde::de::DeserializeOwned,
        TError: serde::de::DeserializeOwned + Into<Error>,
    {
        self.parse::<TResponse, TError>(hyper::StatusCode::OK)
    }

    pub fn parse<TResponse, TError>(
        self,
        expected_status: hyper::StatusCode,
    ) -> Result<TResponse, Error>
    where
        TResponse: serde::de::DeserializeOwned,
        TError: serde::de::DeserializeOwned + Into<Error>,
    {
        if self.status == expected_status {
            let response: TResponse = serde_json::from_slice(&self.body)
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

            Ok(response)
        } else if self.status.is_client_error() || self.status.is_server_error() {
            let error: TError = serde_json::from_slice(&self.body)
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

            Err(error.into())
        } else {
            Err(Error::new(
                ErrorKind::InvalidData,
                "invalid HTTP status code",
            ))
        }
    }
}
