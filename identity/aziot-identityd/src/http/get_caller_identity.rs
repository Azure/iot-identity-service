pub(super) fn handle(
    req: hyper::Request<hyper::Body>,
    inner: std::sync::Arc<aziot_identityd::Server>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, hyper::Request<hyper::Body>>> + Send>> {
    Box::pin(async move {
        if req.uri().path() != "/identities/identity" {
            return Err(req);
        }

        //TODO: Insert caller to module_id mapping lookup here
        let module_id = String::from("callerid");

        let (http::request::Parts { method, .. }, _) = req.into_parts();

        if method != hyper::Method::GET {
            return Ok(super::err_response(
                hyper::StatusCode::METHOD_NOT_ALLOWED,
                Some((hyper::header::ALLOW, "POST")),
                "method not allowed".into(),
            ));
        }

        let res = match inner.get_module_identity(module_id) {
            Ok(v) => v,
            Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
        };
        let res = aziot_identity_common_http::get_module_identity::Response { identity: res };

        let res = super::json_response(hyper::StatusCode::OK, &res);
        Ok(res)
    })
}
