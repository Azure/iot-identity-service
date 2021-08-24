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
    request_with_headers(client, method, uri, None, body).await
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
{
    let (res_status_code, headers, body) = make_call(client, method, uri, headers, body).await?;
    validate_json(headers)?;

    match res_status_code {
        res_status_code if res_status_code.is_success() => {
            let res = serde_json::from_slice(&body)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            Ok(res)
        }

        res_status_code
            if res_status_code.is_client_error() || res_status_code.is_server_error() =>
        {
            let res: super::ErrorBody<'static> = serde_json::from_slice(&body)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            Err(std::io::Error::new(std::io::ErrorKind::Other, res.message))
        }

        _ => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "malformed HTTP response",
        )),
    }
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
    request_with_headers_no_content(client, method, uri, None, body).await
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
{
    let (res_status_code, headers, body) = make_call(client, method, uri, headers, body).await?;

    match res_status_code {
        res_status_code if res_status_code.is_success() => Ok(()),

        res_status_code
            if res_status_code.is_client_error() || res_status_code.is_server_error() =>
        {
            validate_json(headers)?;

            let res: super::ErrorBody<'static> = serde_json::from_slice(&body)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            Err(std::io::Error::new(std::io::ErrorKind::Other, res.message))
        }

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
    body: Option<&TRequest>,
) -> std::io::Result<(hyper::StatusCode, hyper::HeaderMap, hyper::body::Bytes)>
where
    hyper::Uri: TryFrom<TUri>,
    <hyper::Uri as TryFrom<TUri>>::Error: Into<http::Error>,
    TRequest: serde::Serialize,
{
    let mut req = hyper::Request::builder().method(method).uri(uri);

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

    let response = client
        .request(req)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let (
        http::response::Parts {
            status, headers, ..
        },
        body,
    ) = response.into_parts();

    let body = hyper::body::to_bytes(body)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    Ok((status, headers, body))
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
