// Copyright (c) Microsoft. All rights reserved.

lazy_static::lazy_static! {
	static ref URI_REGEX: regex::Regex =
		regex::Regex::new("^/(?P<type>(key|keypair))/(?P<keyId>[^/]+)$")
		.expect("hard-coded regex must compile");
}

pub(super) fn handle(
	req: hyper::Request<hyper::Body>,
	inner: std::sync::Arc<futures_util::lock::Mutex<aziot_keyd::Server>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, hyper::Request<hyper::Body>>> + Send>> {
	Box::pin(async move {
		let path = req.uri().path().to_owned();
		let captures = match URI_REGEX.captures(path.as_str()) {
			Some(captures) => captures,
			None => return Err(req),
		};

		let type_ = &captures["type"];
	
		let key_id = &captures["keyId"];
		let key_id = percent_encoding::percent_decode_str(key_id).decode_utf8();
		let key_id = match key_id {
			Ok(key_id) => key_id.into_owned(),
			Err(err) => return Ok(super::err_response(
				hyper::StatusCode::BAD_REQUEST,
				None,
				super::error_to_message(&err).into(),
			)),
		};

		let (http::request::Parts { method, .. }, _) = req.into_parts();

		if method != hyper::Method::GET {
			return Ok(super::err_response(
				hyper::StatusCode::METHOD_NOT_ALLOWED,
				Some((hyper::header::ALLOW, "GET")),
				"method not allowed".into(),
			));
		}

		let mut inner = inner.lock().await;
		let inner = &mut *inner;

		let handle = match type_ {
			"keypair" => match inner.load_key_pair(&key_id) {
				Ok(handle) => handle,
				Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
			},
			"key" => match inner.load_key(&key_id) {
				Ok(handle) => handle,
				Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
			},
			type_ => return Ok(super::err_response(
				hyper::StatusCode::BAD_REQUEST,
				None,
				format!("invalid type {:?}", type_).into())),
		};

		let res = aziot_key_common_http::load::Response {
			handle,
		};
		let res = super::json_response(hyper::StatusCode::OK, &res);
		Ok(res)
	})
}
