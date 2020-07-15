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
                Some((hyper::header::ALLOW, "GET")),
                "method not allowed".into(),
            ));
        }

        let response = aziot_identity_common_http::get_trust_bundle::Response {
            certificate: aziot_cert_common_http::Pem { 0: std::vec::Vec::default() }
        };

        let response = super::json_response(hyper::StatusCode::OK, &response);
        Ok(response)

        }
    )
}
