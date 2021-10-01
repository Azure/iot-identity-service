// Copyright (c) Microsoft. All rights reserved.

use std::convert::TryFrom;
use std::str::FromStr;

pub async fn request<TRequest, TResponse>(
    client: &hyper::Client<super::Connector, hyper::Body>,
    method: http::Method,
    uri: &str,
    body: Option<&TRequest>,
) -> std::io::Result<TResponse>
where
    TRequest: serde::Serialize,
    TResponse: serde::de::DeserializeOwned,
{
    request_internal(client, method, uri, None, None, body, true).await
}

pub async fn request_with_retry<TRequest, TResponse>(
    client: &hyper::Client<super::Connector, hyper::Body>,
    method: http::Method,
    uri: &str,
    body: Option<&TRequest>,
    max_retries: u32,
) -> std::io::Result<TResponse>
where
    TRequest: serde::Serialize,
    TResponse: serde::de::DeserializeOwned,
{
    request_internal(client, method, uri, None, Some(max_retries), body, true).await
}

pub async fn request_with_headers<TUri, TRequest, TResponse>(
    client: &hyper::Client<super::Connector, hyper::Body>,
    method: http::Method,
    uri: TUri,
    headers: Option<&[(&str, &str)]>,
    body: Option<&TRequest>,
) -> std::io::Result<TResponse>
where
    hyper::Uri: TryFrom<TUri>,
    <hyper::Uri as TryFrom<TUri>>::Error: Into<http::Error>,
    TRequest: serde::Serialize,
    TResponse: serde::de::DeserializeOwned,
    TUri: Clone,
{
    request_internal(client, method, uri, headers, None, body, true).await
}

pub async fn request_no_content<TRequest>(
    client: &hyper::Client<super::Connector, hyper::Body>,
    method: http::Method,
    uri: &str,
    body: Option<&TRequest>,
) -> std::io::Result<()>
where
    TRequest: serde::Serialize,
{
    request_internal(client, method, uri, None, None, body, false).await
}

pub async fn request_no_content_with_retry<TRequest>(
    client: &hyper::Client<super::Connector, hyper::Body>,
    method: http::Method,
    uri: &str,
    body: Option<&TRequest>,
    max_retries: u32,
) -> std::io::Result<()>
where
    TRequest: serde::Serialize,
{
    request_internal(client, method, uri, None, Some(max_retries), body, false).await
}

pub async fn request_with_headers_no_content<TUri, TRequest>(
    client: &hyper::Client<super::Connector, hyper::Body>,
    method: http::Method,
    uri: TUri,
    headers: Option<&[(&str, &str)]>,
    body: Option<&TRequest>,
) -> std::io::Result<()>
where
    hyper::Uri: TryFrom<TUri>,
    <hyper::Uri as TryFrom<TUri>>::Error: Into<http::Error>,
    TRequest: serde::Serialize,
    TUri: Clone,
{
    request_internal(client, method, uri, headers, None, body, false).await
}

async fn request_internal<TUri, TRequest, TResponse>(
    client: &hyper::Client<super::Connector, hyper::Body>,
    method: http::Method,
    uri: TUri,
    headers: Option<&[(&str, &str)]>,
    max_retries: Option<u32>,
    body: Option<&TRequest>,
    has_response: bool,
) -> std::io::Result<TResponse>
where
    hyper::Uri: TryFrom<TUri>,
    <hyper::Uri as TryFrom<TUri>>::Error: Into<http::Error>,
    TRequest: serde::Serialize,
    TResponse: serde::de::DeserializeOwned,
    TUri: Clone,
{
    let (res_status_code, headers, body) =
        make_call(client, method, uri, headers, max_retries.unwrap_or(0), body).await?;

    match res_status_code {
        // Successful call with response
        res_status_code if has_response && res_status_code.is_success() => {
            validate_json(headers)?;

            let res = serde_json::from_slice(&body)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            Ok(res)
        }

        // Successful call with no response
        res_status_code
            if res_status_code.is_success()
                || res_status_code == hyper::StatusCode::NOT_MODIFIED =>
        {
            let res = serde_json::from_slice(b"null").expect("Deserializing null type cannot fail");
            Ok(res)
        }

        // Expected error
        res_status_code
            if res_status_code.is_client_error() || res_status_code.is_server_error() =>
        {
            validate_json(headers)?;

            let res: super::ErrorBody<'static> = serde_json::from_slice(&body)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            Err(std::io::Error::new(std::io::ErrorKind::Other, res.message))
        }

        // Unknown error
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "malformed HTTP response",
        )),
    }
}

async fn make_call<TUri, TRequest>(
    client: &hyper::Client<super::Connector, hyper::Body>,
    method: http::Method,
    uri: TUri,
    headers: Option<&[(&str, &str)]>,
    max_retries: u32,
    body: Option<&TRequest>,
) -> std::io::Result<(hyper::StatusCode, hyper::HeaderMap, hyper::body::Bytes)>
where
    hyper::Uri: TryFrom<TUri>,
    <hyper::Uri as TryFrom<TUri>>::Error: Into<http::Error>,
    TRequest: serde::Serialize,
    TUri: Clone,
{
    let mut retry_num = 0;
    loop {
        let mut req = hyper::Request::builder()
            .method(method.clone())
            .uri(uri.clone());

        if let Some(headers) = headers {
            if let Some(headers_map) = req.headers_mut() {
                for (key, value) in headers {
                    headers_map.insert(
                        headers::HeaderName::from_str(key)
                            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?,
                        headers::HeaderValue::from_str(value)
                            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?,
                    );
                }
            }
        }

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

        let response = client.request(req).await;
        match response {
            Ok(response) => {
                let (
                    http::response::Parts {
                        status, headers, ..
                    },
                    body,
                ) = response.into_parts();

                let body = hyper::body::to_bytes(body)
                    .await
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

                return Ok((status, headers, body));
            }
            Err(err) if err.is_closed() && retry_num < max_retries => {
                log::warn!(
                    "Connection Closed. Retrying (attempt {} of {}).",
                    retry_num + 1,
                    max_retries + 1,
                );

                retry_num += 1;
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                continue;
            }
            Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, err)),
        }
    }
}

fn validate_json(headers: hyper::HeaderMap) -> std::io::Result<()> {
    for (header_name, header_value) in headers {
        if header_name == Some(hyper::header::CONTENT_TYPE) {
            let value = header_value
                .to_str()
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            if value == "application/json" {
                return Ok(());
            }
        }
    }

    Err(std::io::Error::new(
        std::io::ErrorKind::Other,
        "malformed HTTP response, expected content type application/json",
    ))
}

#[cfg(test)]
mod test {
    #[test]
    fn unit_type_deserializes() {
        let _: () = serde_json::from_slice(b"null").expect("Deserializing null type cannot fail");
    }
}
