pub(super) fn handle(
    req: hyper::Request<hyper::Body>,
    inner: std::sync::Arc<aziot_identityd::Server>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, hyper::Request<hyper::Body>>> + Send>> {
    Box::pin(async move {
        if req.uri().path() != "/identities/device/reprovision" {
            return Err(req);
        }

        let (http::request::Parts { method, .. }, _body) = req.into_parts();

        if method != hyper::Method::POST {
            return Ok(super::err_response(
                hyper::StatusCode::METHOD_NOT_ALLOWED,
                Some((hyper::header::ALLOW, "POST")),
                "method not allowed".into(),
            ));
        }

        match inner.reprovision_device() {
            Ok(()) => (),
            Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
        };

        let res =
            hyper::Response::builder()
                .status(hyper::StatusCode::NO_CONTENT)
                .body(Default::default())
                .expect("cannot fail to serialize hyper response");
        Ok(res)
    })
}
