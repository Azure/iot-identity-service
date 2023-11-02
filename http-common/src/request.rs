// Copyright (c) Microsoft. All rights reserved.

use std::io::{Error, ErrorKind};

use crate::backoff::DEFAULT_BACKOFF;

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
    #[must_use]
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

    #[must_use]
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

    #[must_use]
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

    #[must_use]
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

    #[must_use]
    pub fn with_retry(mut self, retries: u32) -> Self {
        self.retries = retries;

        self
    }

    #[must_use]
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

    pub async fn response(self, has_body: bool) -> Result<HttpResponse, Error> {
        let (status, _, body) = self.process_request(has_body).await?;

        let body = if let Some(body) = body {
            body
        } else {
            hyper::body::Bytes::new()
        };

        Ok(HttpResponse { status, body })
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
        has_response_body: bool,
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

        loop {
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

            let mut is_throttled = false;
            let response_future = async {
                match client.request(request).await {
                    Ok(response) => {
                        let (
                            http::response::Parts {
                                status: response_status,
                                headers: response_headers,
                                ..
                            },
                            response_body,
                        ) = response.into_parts();

                        // Make sure to download body inside the timeout
                        let response_body = if has_response_body {
                            let response_body = hyper::body::to_bytes(response_body)
                                .await
                                .map_err(|err| Error::new(ErrorKind::Other, err))?;

                            Some(response_body)
                        } else {
                            None
                        };

                        // if response throttled, go into exponential backoff
                        if response_status == http::StatusCode::TOO_MANY_REQUESTS {
                            is_throttled = true;
                            Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                "429: Too many requests",
                            ))
                        } else {
                            // Return results
                            Ok((response_status, response_headers, response_body))
                        }
                    }
                    Err(err) => {
                        if err.is_connect() {
                            // Network error.
                            Err(std::io::Error::new(std::io::ErrorKind::NotConnected, err))
                        } else {
                            Err(std::io::Error::new(std::io::ErrorKind::Other, err))
                        }
                    }
                }
            };

            let err = match tokio::time::timeout(self.timeout, response_future).await {
                Ok(response) => match response {
                    Ok(response) => return Ok(response),
                    Err(err) => err,
                },

                Err(timeout) => timeout.into(),
            };

            if is_throttled {
                if let Some(backoff_duration) =
                    DEFAULT_BACKOFF.get_backoff_duration(current_attempt)
                {
                    log::warn!(
                        "HTTP request throttled (attempt {} of {}). Sleeping for {} seconds.",
                        current_attempt,
                        DEFAULT_BACKOFF.max_retries() + 1,
                        backoff_duration.as_secs()
                    );
                    tokio::time::sleep(backoff_duration).await;
                } else {
                    log::warn!(
                        "Final HTTP request throttled (attempt {} of {}).",
                        current_attempt,
                        DEFAULT_BACKOFF.max_retries() + 1,
                    );
                    return Err(err);
                }
            } else {
                log::warn!(
                    "Failed to send HTTP request (attempt {} of {}): {}",
                    current_attempt,
                    self.retries + 1,
                    err
                );

                if current_attempt > self.retries {
                    return Err(err);
                }

                // Wait a short time between failed requests.
                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            }

            current_attempt += 1;
        }
    }
}

#[derive(Debug)]
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
        self.parse::<TResponse, TError>(&[hyper::StatusCode::OK])
    }

    pub fn parse<TResponse, TError>(
        self,
        expected_statuses: &[hyper::StatusCode],
    ) -> Result<TResponse, Error>
    where
        TResponse: serde::de::DeserializeOwned,
        TError: serde::de::DeserializeOwned + Into<Error>,
    {
        if expected_statuses.contains(&self.status) {
            let response: TResponse = serde_json::from_slice(&self.body)
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

            Ok(response)
        } else if self.status.is_client_error() || self.status.is_server_error() {
            let error: TError = serde_json::from_slice(&self.body)
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

            Err(error.into())
        } else {
            Err(Error::new(
                ErrorKind::Other,
                format!(
                    "Expected one of {:?}, got {}",
                    expected_statuses, self.status
                ),
            ))
        }
    }
}

/// Using this test:
///
/// This test can only be run manually. It will send thousands of concurrent tests to iothub to induce a throttle.
/// This should cause the exponential backoff with jitter to trigger.
///
/// To run this test, first create a new device in a hub. Then use the az cli to generate a device token:
/// `az iot hub generate-sas-token --hub-name "your-hub" --device-id "your-device-id"`
///
/// Then simply set the `HUB_HOSTNAME`, `DEVICE_ID`, and `SAS_TOKEN` variables and run the test using
/// `RUST_LOG=info cargo test test_backoff -- --nocapture --ignored`
///
/// A successful run should print lots of throttle warnings, but never error. The throttle warnings should have some jitter.
/// It will never return and must be manually canceled.
///
/// Example output:
/// ```
/// [2023-01-31T05:03:18Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 66 seconds.
/// Finished request 2201 (57) in 9.593452176
/// Making request 2219 (57)
/// [2023-01-31T05:03:19Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 67 seconds.
/// Finished request 2209 (677) in 6.339969904
/// Making request 2220 (677)
/// [2023-01-31T05:03:20Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 62 seconds.
/// Finished request 1725 (116) in 274.212254168
/// Making request 2221 (116)
/// [2023-01-31T05:03:20Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 61 seconds.
/// [2023-01-31T05:03:21Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 66 seconds.
/// Finished request 1737 (271) in 272.654453645
/// Making request 2222 (271)
/// Finished request 2040 (340) in 108.331706338
/// Making request 2223 (340)
/// [2023-01-31T05:03:22Z WARN  http_common::request] HTTP request throttled (attempt 2 of 5). Sleeping for 121 seconds.
/// Finished request 2054 (59) in 105.782412118
/// Making request 2224 (59)
/// [2023-01-31T05:03:22Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 62 seconds.
/// Finished request 2177 (457) in 36.547918943
/// Making request 2225 (457)
/// [2023-01-31T05:03:23Z WARN  http_common::request] HTTP request throttled (attempt 3 of 5). Sleeping for 186 seconds.
/// [2023-01-31T05:03:23Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 69 seconds.
/// Finished request 2039 (890) in 109.541071346
/// Making request 2226 (890)
/// Finished request 1684 (52) in 280.208850293
/// Making request 2227 (52)
/// [2023-01-31T05:03:23Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 64 seconds.
/// Finished request 2041 (223) in 109.602108785
/// Making request 2228 (223)
/// Finished request 2035 (446) in 110.378473331
/// Making request 2229 (446)
/// [2023-01-31T05:03:24Z WARN  http_common::request] HTTP request throttled (attempt 2 of 5). Sleeping for 139 seconds.
/// Finished request 2030 (865) in 111.498652518
/// Making request 2230 (865)
/// [2023-01-31T05:03:25Z WARN  http_common::request] HTTP request throttled (attempt 2 of 5). Sleeping for 122 seconds.
/// Finished request 2043 (793) in 110.364761699
/// Making request 2231 (793)
/// Finished request 1707 (341) in 280.771491736
/// Making request 2232 (341)
/// Finished request 1673 (506) in 282.369761148
/// Making request 2233 (506)
/// [2023-01-31T05:03:25Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 63 seconds.
/// Finished request 2190 (634) in 28.784852222
/// Making request 2234 (634)
/// [2023-01-31T05:03:26Z WARN  http_common::request] HTTP request throttled (attempt 2 of 5). Sleeping for 134 seconds.
/// [2023-01-31T05:03:26Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 60 seconds.
/// Finished request 2073 (458) in 104.998458255
/// Making request 2235 (458)
/// Finished request 1941 (815) in 140.595490728
/// Making request 2236 (815)
/// [2023-01-31T05:03:27Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 64 seconds.
/// Finished request 2220 (677) in 8.386235762
/// Making request 2237 (677)
/// Finished request 1739 (630) in 278.837086908
/// Making request 2238 (630)
/// Finished request 2213 (475) in 13.79317502
/// Making request 2239 (475)
/// [2023-01-31T05:03:30Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 65 seconds.
/// [2023-01-31T05:03:31Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 60 seconds.
/// [2023-01-31T05:03:32Z WARN  http_common::request] HTTP request throttled (attempt 2 of 5). Sleeping for 129 seconds.
/// [2023-01-31T05:03:32Z WARN  http_common::request] HTTP request throttled (attempt 1 of 5). Sleeping for 69 seconds.
/// Finished request 2208 (623) in 19.796385227000002
/// Making request 2240 (623)
/// Finished request 2240 (623) in 0.060063126
/// Making request 2241 (623)
/// [2023-01-31T05:03:32Z WARN  http_common::request] HTTP request
/// ```
#[cfg(test)]
mod tests {
    const HUB_HOSTNAME: &str = "your-hubname-here.azurecr.io";
    const DEVICE_ID: &str = "your-deviceid";
    const SAS_TOKEN: &str = "sas token generated by az iot hub generate-sas-token --hub-name 'your-hubname-here' --device-id 'your-device-id'";

    use std::{
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        },
        time::{Duration, Instant},
    };

    use http::header::{AUTHORIZATION, CONTENT_TYPE};
    use hyper_openssl::HttpsConnector;

    use aziot_identity_common::hub::Module;

    use super::*;

    #[tokio::test]
    #[ignore]
    async fn test_backoff_manual() {
        if HUB_HOSTNAME == "your-hubname-here.azurecr.io" {
            return;
        }

        env_logger::init();

        let count = Arc::new(AtomicUsize::new(1));
        for i in 1..1000 {
            println!("Starting loop {}", i);
            let count = count.clone();

            tokio::spawn(async move {
                loop {
                    let j = count.fetch_add(1, Ordering::Relaxed);

                    let request_num = format!("{} ({})", j, i);
                    if let Err(e) = query_hub(&request_num).await {
                        println!("Error: {}", e);
                    }

                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            });
        }

        std::future::pending::<()>().await;
    }

    async fn query_hub(i: &str) -> Result<(), Box<Error>> {
        println!("Making request {}", i);
        let timer = Instant::now();

        let uri = format!(
            "https://{}/devices/{}/modules?api-version=2020-05-31-preview",
            HUB_HOSTNAME, DEVICE_ID
        );

        let mut request = HttpRequest::<Option<()>, _>::get(HttpsConnector::new().unwrap(), &uri)
            .with_retry(0)
            .with_timeout(Duration::from_secs(60));
        request.add_header(CONTENT_TYPE, "application/json")?;
        request.add_header(AUTHORIZATION, SAS_TOKEN)?;

        let response = request.json_response().await?;
        let _modules = response.parse_expect_ok::<Vec<Module>, HubError>()?;

        println!(
            "Finished request {} in {}",
            i,
            timer.elapsed().as_secs_f64()
        );

        Ok(())
    }

    #[derive(Debug, serde::Deserialize)]
    struct HubError {
        #[serde(rename = "Message")]
        pub message: String,
    }

    impl std::convert::From<HubError> for Error {
        fn from(err: HubError) -> Error {
            Error::new(ErrorKind::Other, err.message)
        }
    }
}
