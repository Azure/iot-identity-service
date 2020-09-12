// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
	inner: std::sync::Arc<futures_util::lock::Mutex<aziot_keyd::Server>>,
}

impl http_common::server::Route for Route {
	type ApiVersion = aziot_key_common_http::ApiVersion;
	fn api_version() -> std::ops::Range<Self::ApiVersion> {
		(aziot_key_common_http::ApiVersion::V2020_09_01)..(aziot_key_common_http::ApiVersion::Max)
	}

	type Server = super::Server;
	fn from_uri(
		server: &Self::Server,
		path: &str,
		_query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
	) -> Option<Self> {
		if path != "/derivedkey" {
			return None;
		}

		Some(Route {
			inner: server.inner.clone(),
		})
	}

	type DeleteBody = serde::de::IgnoredAny;
	type DeleteResponse = ();

	type GetResponse = ();

	type PostBody = aziot_key_common_http::create_derived_key::Request;
	type PostResponse = aziot_key_common_http::create_derived_key::Response;
	fn post(self, body: Option<Self::PostBody>) -> http_common::server::RouteResponse<Option<Self::PostResponse>> {
		Box::pin(async move {
			let body = body.ok_or_else(|| http_common::server::Error {
				status_code: http::StatusCode::BAD_REQUEST,
				message: "missing request body".into(),
			})?;

			let mut inner = self.inner.lock().await;
			let inner = &mut *inner;

			let handle = match inner.create_derived_key(&body.base_handle, &body.derivation_data.0) {
				Ok(handle) => handle,
				Err(err) => return Err(super::to_http_error(&err)),
			};

			let res = aziot_key_common_http::create_derived_key::Response {
				handle,
			};
			Ok((hyper::StatusCode::OK, Some(res)))
		})
	}

	type PutBody = serde::de::IgnoredAny;
	type PutResponse = ();
}
