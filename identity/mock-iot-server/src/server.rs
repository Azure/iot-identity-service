// Copyright (c) Microsoft. All rights reserved.

pub(crate) struct ParsedRequest {
    pub method: hyper::Method,
    pub uri: String,
    pub headers: std::collections::HashMap<String, String>,
    pub body: Option<String>,
}

impl ParsedRequest {
    async fn from_http(req: hyper::Request<hyper::Body>) -> Result<Self, Response> {
        println!();
        println!("----");

        let method = req.method().clone();
        let uri = req.uri().to_string();
        println!("> {} {} {:?}", method, uri, req.version());

        let mut headers = std::collections::HashMap::with_capacity(req.headers().len());
        for (key, value) in req.headers() {
            let key = key.to_string();
            let value = value
                .to_str()
                .map_err(|_| Response::bad_request("bad header value"))?
                .to_string();

            println!("> {}: {}", key, value);
            headers.insert(key, value);
        }

        let body = hyper::body::to_bytes(req.into_body())
            .await
            .map_err(|_| Response::bad_request("unable to get body"))?
            .to_vec();

        let body = if body.is_empty() {
            None
        } else {
            let body = std::str::from_utf8(&body)
                .map_err(|_| Response::bad_request("unable to parse body"))?
                .to_string();

            println!();
            println!("{}", body);

            Some(body)
        };

        Ok(ParsedRequest {
            method,
            uri,
            headers,
            body,
        })
    }
}

pub(crate) enum Response {
    Error {
        status: hyper::StatusCode,
        message: String,
    },

    Json {
        status: hyper::StatusCode,
        body: String,
    },
}

impl Response {
    pub fn bad_request(message: impl std::fmt::Display) -> Self {
        Response::Error {
            status: hyper::StatusCode::BAD_REQUEST,
            message: message.to_string(),
        }
    }

    pub fn not_found(message: impl std::fmt::Display) -> Self {
        Response::Error {
            status: hyper::StatusCode::NOT_FOUND,
            message: message.to_string(),
        }
    }

    pub fn method_not_allowed(method: &hyper::Method) -> Self {
        Response::Error {
            status: hyper::StatusCode::METHOD_NOT_ALLOWED,
            message: format!("{} not allowed", method),
        }
    }

    pub fn json(status: hyper::StatusCode, body: impl serde::Serialize) -> Self {
        let body = serde_json::to_string(&body).unwrap();

        Response::Json { status, body }
    }

    #[allow(clippy::wrong_self_convention)] // This function should consume self.
    pub fn to_http(self) -> hyper::Response<hyper::Body> {
        let mut response = hyper::Response::builder();

        let (status, body, debug_body) = match self {
            Response::Error { status, message } => {
                println!();
                println!("{}", message);

                (status, hyper::Body::empty(), None)
            }

            Response::Json { status, body } => {
                response = response.header(hyper::header::CONTENT_TYPE, "application/json");

                (status, hyper::Body::from(body.clone()), Some(body))
            }
        };

        println!();
        println!("< {}", status);

        let response = response.status(status).body(body).unwrap();

        for (key, value) in response.headers() {
            println!("< {}: {}", key, value.to_str().unwrap());
        }

        if let Some(body) = debug_body {
            println!();
            println!("{}", body);
        }

        response
    }
}

pub(crate) struct ContextInner {
    pub in_progress_operations: std::collections::BTreeMap<
        String,
        aziot_dps_client_async::model::RegistrationOperationStatus,
    >,
    pub devices: std::collections::BTreeMap<
        String,
        std::collections::BTreeSet<aziot_identity_common::hub::Module>,
    >,
    pub trust_bundle: Option<aziot_dps_client_async::model::TrustBundle>,
    pub enable_identity_certs: bool,
    pub enable_server_certs: bool,
    pub endpoint: String,
}

impl ContextInner {
    pub fn new(options: &crate::Options) -> Self {
        ContextInner {
            in_progress_operations: std::collections::BTreeMap::new(),
            devices: std::collections::BTreeMap::new(),
            trust_bundle: crate::certs::trust_bundle::read_trust_bundle(
                options.trust_bundle_certs_dir.as_ref(),
            ),
            enable_identity_certs: options.enable_identity_certs,
            enable_server_certs: options.enable_server_certs,
            endpoint: format!("localhost:{}", options.port),
        }
    }
}

pub(crate) type Context = std::sync::Arc<std::sync::Mutex<ContextInner>>;

pub(crate) async fn serve_request(
    mut context: Context,
    req: hyper::Request<hyper::Body>,
) -> Result<hyper::Response<hyper::Body>, std::convert::Infallible> {
    let req = match ParsedRequest::from_http(req).await {
        Ok(req) => req,
        Err(response) => return Ok(response.to_http()),
    };

    if let Some(response) = crate::dps::process_request(&req, &mut context) {
        return Ok(response.to_http());
    }

    if let Some(response) = crate::hub::process_request(&req, &mut context) {
        return Ok(response.to_http());
    }

    Ok(Response::not_found(format!("{} not found", req.uri)).to_http())
}

pub(crate) fn get_param(captures: &regex::Captures<'_>, name: &str) -> Result<String, Response> {
    let value = &captures[name];

    let value = percent_encoding::percent_decode_str(value)
        .decode_utf8()
        .map_err(|_| Response::bad_request(format!("bad {}", name)))?
        .to_string();

    Ok(value)
}
