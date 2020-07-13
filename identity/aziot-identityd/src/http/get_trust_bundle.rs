pub(super) fn handle(
    req: hyper::Request<hyper::Body>,
    _inner: std::sync::Arc<aziot_identityd::Server>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, hyper::Request<hyper::Body>>> + Send>> {
    Box::pin(async move {
        if req.uri().path() != "/trust-bundle" {
            return Err(req);
        }

        let (http::request::Parts { method, .. }, _body) = req.into_parts();

        if method != hyper::Method::GET {
            return Ok(super::err_response(
                hyper::StatusCode::METHOD_NOT_ALLOWED,
                Some((hyper::header::ALLOW, "POST")),
                "method not allowed".into(),
            ));
        }

        let res = aziot_identity_common_http::get_trust_bundle::Response {
            certificate: aziot_identity_common_http::get_trust_bundle::Pem { 0: std::vec::Vec::default() }
        };

        let res = super::json_response(hyper::StatusCode::OK, &res);
        Ok(res)

        }
    )
}
