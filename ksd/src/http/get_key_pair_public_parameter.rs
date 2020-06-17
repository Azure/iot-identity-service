use ks_common::KeysServiceInterface;

lazy_static::lazy_static! {
	static ref URI_REGEX: regex::Regex =
		regex::Regex::new("^/parameters/(?P<parameterName>[^/]+)$")
		.expect("hard-coded regex must compile");
}

pub(super) fn handle(
	req: hyper::Request<hyper::Body>,
	inner: std::sync::Arc<ksd::Server>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, hyper::Request<hyper::Body>>> + Send>> {
	Box::pin(async move {
		let captures = match URI_REGEX.captures(req.uri().path()) {
			Some(captures) => captures,
			None => return Err(req),
		};

		let parameter_name = &captures["parameterName"];
		let parameter_name = percent_encoding::percent_decode_str(parameter_name).decode_utf8();
		let parameter_name = match parameter_name {
			Ok(parameter_name) => parameter_name.into_owned(),
			Err(err) => return Ok(super::err_response(
				hyper::StatusCode::BAD_REQUEST,
				None,
				super::error_to_message(&err).into(),
			)),
		};

		let (http::request::Parts { method, headers, .. }, body) = req.into_parts();
		let content_type = headers.get(hyper::header::CONTENT_TYPE).and_then(|value| value.to_str().ok());

		if method != hyper::Method::POST {
			return Ok(super::err_response(
				hyper::StatusCode::METHOD_NOT_ALLOWED,
				Some((hyper::header::ALLOW, "POST")),
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
		let body: ks_common_http::get_key_pair_public_parameter::Request = match serde_json::from_slice(&body) {
			Ok(body) => body,
			Err(err) => return Ok(super::err_response(
				hyper::StatusCode::UNPROCESSABLE_ENTITY,
				None,
				super::error_to_message(&err).into(),
			)),
		};

		let parameter_value = match inner.get_key_pair_public_parameter(&body.key_handle, &parameter_name) {
			Ok(parameter_value) => parameter_value,
			Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
		};

		let res = ks_common_http::get_key_pair_public_parameter::Response {
			value: parameter_value,
		};
		let res = super::json_response(hyper::StatusCode::OK, &res);
		Ok(res)
	})
}
