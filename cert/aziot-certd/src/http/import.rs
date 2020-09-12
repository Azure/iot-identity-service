// Copyright (c) Microsoft. All rights reserved.

lazy_static::lazy_static! {
	static ref URI_REGEX: regex::Regex =
		regex::Regex::new("^/certificates/(?P<certId>[^/]+)$")
		.expect("hard-coded regex must compile");
}

pub(super) struct Route {
	inner: std::sync::Arc<futures_util::lock::Mutex<aziot_certd::Server>>,
	cert_id: String,
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
		let captures = URI_REGEX.captures(path)?;

		let cert_id = &captures["certId"];
		let cert_id = percent_encoding::percent_decode_str(cert_id).decode_utf8().ok()?;

		Some(Route {
			inner: server.inner.clone(),
			cert_id: cert_id.into_owned(),
		})
	}

	type DeleteBody = serde::de::IgnoredAny;
	type DeleteResponse = ();

	type GetResponse = ();

	type PostBody = serde::de::IgnoredAny;
	type PostResponse = ();

	type PutBody = aziot_cert_common_http::import_cert::Request;
	type PutResponse = aziot_cert_common_http::import_cert::Response;
	fn put(self, body: Self::PutBody) -> http_common::server::RouteResponse<Self::PutResponse> {
		Box::pin(async move {
			let mut inner = self.inner.lock().await;
			let inner = &mut *inner;

			match inner.import_cert(&self.cert_id, &body.pem.0) {
				Ok(()) => (),
				Err(err) => return Err(super::to_http_error(&err)),
			};

			let res = aziot_cert_common_http::import_cert::Response {
				pem: body.pem,
			};
			Ok((hyper::StatusCode::CREATED, res))
		})
	}
}
