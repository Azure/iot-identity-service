// Copyright (c) Microsoft. All rights reserved.

pub(super) fn handle(
    req: hyper::Request<hyper::Body>,
    inner: std::sync::Arc<futures_util::lock::Mutex<aziot_identityd::Server>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, hyper::Request<hyper::Body>>> + Send>> {
    Box::pin(async move {
        if req.uri().path() != "/identities/device/reprovision" {
            return Err(req);
        }

        let mut inner = inner.lock().await;
		let inner = &mut *inner;

        let user = aziot_identityd::auth::Uid(0);
        let auth_id = match inner.authenticator.authenticate(user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
        };

        let (http::request::Parts { method, .. }, _body) = req.into_parts();

        if method != hyper::Method::POST {
            return Ok(super::err_response(
                hyper::StatusCode::METHOD_NOT_ALLOWED,
                Some((hyper::header::ALLOW, "POST")),
                "method not allowed".into(),
            ));
        }

        //TODO: get uid from UDS
        match inner.reprovision_device(auth_id).await {
            Ok(()) => (),
            Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
        };

        let response =
            hyper::Response::builder()
                .status(hyper::StatusCode::NO_CONTENT)
                .body(hyper::body::Body::default())
                .expect("cannot fail to serialize hyper response");
        Ok(response)
    })
}
