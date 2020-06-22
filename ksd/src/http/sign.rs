use ks_common::KeysServiceInterface;

pub(super) fn handle(
	req: hyper::Request<hyper::Body>,
	inner: std::sync::Arc<ksd::Server>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<hyper::Response<hyper::Body>, hyper::Request<hyper::Body>>> + Send>> {
	Box::pin(async move {
		if req.uri().path() != "/sign" {
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
		let body: ks_common_http::sign::Request = match serde_json::from_slice(&body) {
			Ok(body) => body,
			Err(err) => return Ok(super::err_response(
				hyper::StatusCode::UNPROCESSABLE_ENTITY,
				None,
				super::error_to_message(&err).into(),
			)),
		};
		let (mechanism, digest) = match body.parameters {
			ks_common_http::sign::Parameters::Ecdsa { digest } => (ks_common::SignMechanism::Ecdsa, digest),

			ks_common_http::sign::Parameters::RsaPkcs1 { message_digest_algorithm, message } => {
				let message_digest = match &*message_digest_algorithm {
					"sha1" => ks_common::RsaPkcs1MessageDigest::Sha1,
					"sha224" => ks_common::RsaPkcs1MessageDigest::Sha224,
					"sha256" => ks_common::RsaPkcs1MessageDigest::Sha256,
					"sha384" => ks_common::RsaPkcs1MessageDigest::Sha384,
					"sha512" => ks_common::RsaPkcs1MessageDigest::Sha512,
					message_digest_algorithm => return Ok(super::err_response(
						hyper::StatusCode::UNPROCESSABLE_ENTITY,
						None,
						format!("invalid value of parameters.messageDigestAlgorithm {:?}", message_digest_algorithm).into(),
					)),
				};

				(ks_common::SignMechanism::RsaPkcs1 { message_digest }, message)
			},

			ks_common_http::sign::Parameters::HmacSha256 { message } => (ks_common::SignMechanism::HmacSha256, message),
		};

		let signature = match inner.sign(&body.key_handle, mechanism, &digest.0) {
			Ok(signature) => signature,
			Err(err) => return Ok(super::ToHttpResponse::to_http_response(&err)),
		};

		let res = ks_common_http::sign::Response {
			signature: http_common::ByteString(signature),
		};
		let res = super::json_response(hyper::StatusCode::OK, &res);
		Ok(res)
	})
}
