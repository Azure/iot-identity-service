use ks_common::KeysServiceInterface;

pub(super) fn handle(
	req: hyper::Request<hyper::Body>,
	inner: std::sync::Arc<ksd::Server>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, hyper::Request<hyper::Body>>> + Send>> {
	Box::pin(async move {
		if req.uri().path() != "/decrypt" {
			return Err(req);
		}

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
		let body: ks_common_http::decrypt::Request = match serde_json::from_slice(&body) {
			Ok(body) => body,
			Err(err) => return Ok(super::err_response(
				hyper::StatusCode::UNPROCESSABLE_ENTITY,
				None,
				super::error_to_message(&err).into(),
			)),
		};
		let mechanism = match body.parameters {
			ks_common_http::decrypt::Parameters::Aead { iv, aad } => {
				let iv = match base64::decode(&iv) {
					Ok(iv) => iv,
					Err(err) => return Ok(super::err_response(
						hyper::StatusCode::UNPROCESSABLE_ENTITY,
						None,
						super::error_to_message(&err).into(),
					)),
				};

				let aad = match base64::decode(&aad) {
					Ok(aad) => aad,
					Err(err) => return Ok(super::err_response(
						hyper::StatusCode::UNPROCESSABLE_ENTITY,
						None,
						super::error_to_message(&err).into(),
					)),
				};

				ks_common::EncryptMechanism::Aead { iv, aad }
			},
		};
		let ciphertext = match base64::decode(&body.ciphertext) {
			Ok(ciphertext) => ciphertext,
			Err(err) => return Ok(super::err_response(
				hyper::StatusCode::UNPROCESSABLE_ENTITY,
				None,
				super::error_to_message(&err).into(),
			)),
		};

		let plaintext = match inner.decrypt(&body.key_handle, mechanism, &ciphertext) {
			Ok(plaintext) => plaintext,
			Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
		};

		let res = ks_common_http::decrypt::Response {
			plaintext: base64::encode(&plaintext),
		};
		let res = super::json_response(hyper::StatusCode::OK, &res);
		Ok(res)
	})
}
