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

		let (http::request::Parts { method, .. }, _) = req.into_parts();

		let mut inner = inner.lock().await;
		let inner = &mut *inner;

		match method {
			hyper::Method::GET => {
				let pem = inner.get_cert(&cert_id);
				let pem = match pem {
					Ok(pem) => pem,
					Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
				};

				let res = aziot_cert_common_http::get_cert::Response {
					pem: aziot_cert_common_http::Pem(pem),
				};
				let res = super::json_response(hyper::StatusCode::OK, &res);
				Ok(res)
			},

			hyper::Method::DELETE => {
				match inner.delete_cert(&cert_id) {
					Ok(()) => (),
					Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
				};

				let res =
					hyper::Response::builder()
					.status(hyper::StatusCode::NO_CONTENT)
					.body(Default::default())
					.expect("cannot fail to serialize hyper response");
				Ok(res)
			},

			_ => Ok(super::err_response(
				hyper::StatusCode::METHOD_NOT_ALLOWED,
				Some((hyper::header::ALLOW, "GET")),
				"method not allowed".into(),
			)),
		}
	})
}
