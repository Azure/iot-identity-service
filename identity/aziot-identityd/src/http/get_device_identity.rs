pub(super) fn handle(
    req: hyper::Request<hyper::Body>,
    inner: std::sync::Arc<aziot_identityd::Server>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, hyper::Request<hyper::Body>>> + Send>> {
    Box::pin(async move {
        if req.uri().path() != "/identities/device" {
            return Err(req);
        }

        let (http::request::Parts { method, .. }, body) = req.into_parts();

        if method != hyper::Method::GET {
            return Ok(super::err_response(
                hyper::StatusCode::METHOD_NOT_ALLOWED,
                Some((hyper::header::ALLOW, "POST")),
                "method not allowed".into(),
            ));
        }

        let body = match hyper::body::to_bytes(body).await {
            Ok(body) => body,
            Err(err) => return Ok(super::err_response(
                hyper::StatusCode::BAD_REQUEST,
                None,
                super::error_to_message(&err).into(),
            )),
        };

        let body: aziot_identity_common_http::get_device_identity::Request = match serde_json::from_slice(&body) {
            Ok(body) => body,
            Err(err) => return Ok(super::err_response(
                hyper::StatusCode::UNPROCESSABLE_ENTITY,
                None,
                super::error_to_message(&err).into(),
            )),
        };

        let res = match inner.get_device_identity(body.id_type) {
            Ok(v) => v,
            Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
        };
        let res = aziot_identity_common_http::get_device_identity::Response { identity: res };

        let res = super::json_response(hyper::StatusCode::OK, &res);
        Ok(res)
    })
}
