// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
	inner: std::sync::Arc<futures_util::lock::Mutex<aziot_certd::Server>>,
}

impl http_common::server::Route for Route {
	type ApiVersion = aziot_cert_common_http::ApiVersion;
	fn api_version() -> std::ops::Range<Self::ApiVersion> {
		(aziot_cert_common_http::ApiVersion::V2020_09_01)..(aziot_cert_common_http::ApiVersion::Max)
	}

	type Server = super::Server;
	fn from_uri(
		server: &Self::Server,
		path: &str,
		_query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
	) -> Option<Self> {
		if path != "/certificates" {
			return None;
		}

		Some(Route {
			inner: server.inner.clone(),
		})
	}

	type DeleteBody = serde::de::IgnoredAny;
	type DeleteResponse = ();

	type GetResponse = ();

	type PostBody = aziot_cert_common_http::create_cert::Request;
	type PostResponse = aziot_cert_common_http::create_cert::Response;
	fn post(self, body: Option<Self::PostBody>) -> http_common::server::RouteResponse<Option<Self::PostResponse>> {
		Box::pin(async move {
			let body = body.ok_or_else(|| http_common::server::Error {
				status_code: http::StatusCode::BAD_REQUEST,
				message: "missing request body".into(),
			})?;

			let pem = aziot_certd::Server::create_cert(
				self.inner,
				body.cert_id,
				body.csr.0,
				body.issuer.map(|aziot_cert_common_http::create_cert::Issuer { cert_id, private_key_handle }| (cert_id, private_key_handle)),
			).await;
			let pem = match pem {
				Ok(pem) => pem,
				Err(err) => return Err(super::to_http_error(&err)),
			};

			let res = aziot_cert_common_http::create_cert::Response {
				pem: aziot_cert_common_http::Pem(pem),
			};
			Ok((hyper::StatusCode::CREATED, Some(res)))
		})
	}

	type PutBody = serde::de::IgnoredAny;
	type PutResponse = ();
}
