// Copyright (c) Microsoft. All rights reserved.

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
            let res: super::ErrorBody<'static> = serde_json::from_slice(&body)
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

pub async fn request_no_content<TRequest>(
    client: &hyper::Client<super::Connector, hyper::Body>,
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
