// Copyright (c) Microsoft. All rights reserved.

lazy_static::lazy_static! {
	static ref URI_REGEX: regex::Regex =
		regex::Regex::new("^/identities/modules/(?P<moduleId>[^/]+)$")
		.expect("hard-coded regex must compile");
}

pub(super) fn handle(
    req: hyper::Request<hyper::Body>,
    inner: std::sync::Arc<aziot_identityd::Server>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, hyper::Request<hyper::Body>>> + Send>> {
    Box::pin(async move {

        let captures = match URI_REGEX.captures(req.uri().path()) {
            Some(captures) => captures,
            None => return Err(req),
        };

        let module_id = &captures["moduleId"];
        let module_id = percent_encoding::percent_decode_str(module_id).decode_utf8();
        let module_id = match module_id {
            Ok(module_id) => module_id.into_owned(),
            Err(err) => return Ok(super::err_response(
                hyper::StatusCode::BAD_REQUEST,
                None,
                super::error_to_message(&err).into(),
            )),
        };

        let user = aziot_identityd::auth::Uid(0);
        let auth_id = match inner.authenticator.authenticate(user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
        };

        let (http::request::Parts { method, .. }, body) = req.into_parts();

        if method != hyper::Method::GET {
            return Ok(super::err_response(
                hyper::StatusCode::METHOD_NOT_ALLOWED,
                Some((hyper::header::ALLOW, "GET")),
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

        let body: aziot_identity_common_http::get_module_identity::Request = match serde_json::from_slice(&body) {
            Ok(body) => body,
            Err(err) => return Ok(super::err_response(
                hyper::StatusCode::UNPROCESSABLE_ENTITY,
                None,
                super::error_to_message(&err).into(),
            )),
        };

        //TODO: get uid from UDS
        let response = match inner.get_identity(auth_id,&body.id_type, &module_id) {
            Ok(v) => v,
            Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
        };
        let response = aziot_identity_common_http::get_module_identity::Response { identity: response };

        let response = super::json_response(hyper::StatusCode::OK, &response);
        Ok(response)
    })
}
