// Copyright (c) Microsoft. All rights reserved.

pub(super) fn handle(
    req: hyper::Request<hyper::Body>,
    inner: std::sync::Arc<aziot_identityd::Server>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, hyper::Request<hyper::Body>>> + Send>> {
    Box::pin(async move {
        if req.uri().path() != "/identities/identity" {
            return Err(req);
        }

        let user = aziot_identityd::auth::Uid(0);
        let auth_id = match inner.authenticator.authenticate(user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
        };

        let (http::request::Parts { method, .. }, _) = req.into_parts();

        if method != hyper::Method::GET {
            return Ok(super::err_response(
                hyper::StatusCode::METHOD_NOT_ALLOWED,
                Some((hyper::header::ALLOW, "GET")),
                "method not allowed".into(),
            ));
        }

        //TODO: get uid from UDS
        let response = match inner.get_caller_identity(auth_id) {
            Ok(v) => v,
            Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
        };
        let response = aziot_identity_common_http::get_module_identity::Response { identity: response };

        let response = super::json_response(hyper::StatusCode::OK, &response);
        Ok(response)
    })
}
