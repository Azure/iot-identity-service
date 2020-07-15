lazy_static::lazy_static! {
	static ref URI_REGEX: regex::Regex =
		regex::Regex::new("^/certificates/(?P<certId>[^/]+)$")
		.expect("hard-coded regex must compile");
}

pub(super) fn handle(
	req: hyper::Request<hyper::Body>,
	inner: std::sync::Arc<futures_util::lock::Mutex<aziot_certd::Server>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, hyper::Request<hyper::Body>>> + Send>> {
	Box::pin(async move {
		let captures = match URI_REGEX.captures(req.uri().path()) {
			Some(captures) => captures,
			None => return Err(req),
		};

		let cert_id = &captures["certId"];
		let cert_id = percent_encoding::percent_decode_str(cert_id).decode_utf8();
		let cert_id = match cert_id {
			Ok(cert_id) => cert_id.into_owned(),
			Err(err) => return Ok(super::err_response(
				hyper::StatusCode::BAD_REQUEST,
				None,
				super::error_to_message(&err).into(),
			)),
		};

		let (http::request::Parts { method, headers, .. }, body) = req.into_parts();
		let content_type = headers.get(hyper::header::CONTENT_TYPE).and_then(|value| value.to_str().ok());

		if method != hyper::Method::PUT {
			return Ok(super::err_response(
				hyper::StatusCode::METHOD_NOT_ALLOWED,
				Some((hyper::header::ALLOW, "PUT")),
				"method not allowed".into(),
			));
		}

		if content_type.as_deref() != Some("application/json") {
			return Ok(super::err_response(
				hyper::StatusCode::UNSUPPORTED_MEDIA_TYPE,
				None,
				"request body must be application/json".into(),
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
		let body: aziot_cert_common_http::import_cert::Request = match serde_json::from_slice(&body) {
			Ok(body) => body,
			Err(err) => return Ok(super::err_response(
				hyper::StatusCode::UNPROCESSABLE_ENTITY,
				None,
				super::error_to_message(&err).into(),
			)),
		};

		let mut inner = inner.lock().await;
		let inner = &mut *inner;

		match inner.import_cert(&cert_id, &body.pem.0) {
			Ok(()) => (),
			Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
		};

		let res = aziot_cert_common_http::import_cert::Response {
			pem: body.pem,
		};
		let res = super::json_response(hyper::StatusCode::CREATED, &res);
		Ok(res)
	})
}
