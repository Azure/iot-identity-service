// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
	inner: std::sync::Arc<futures_util::lock::Mutex<aziot_identityd::Server>>,
}

impl http_common::server::Route for Route {
	type ApiVersion = aziot_identity_common_http::ApiVersion;
	fn api_version() -> std::ops::Range<Self::ApiVersion> {
		(aziot_identity_common_http::ApiVersion::V2020_09_01)..(aziot_identity_common_http::ApiVersion::Max)
	}

	type Server = super::Server;
	fn from_uri(
		server: &Self::Server,
		path: &str,
		_query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
	) -> Option<Self> {
		if path != "/identities/device/reprovision" {
			return None;
		}

		Some(Route {
			inner: server.inner.clone(),
		})
	}

	type DeleteBody = serde::de::IgnoredAny;
	type DeleteResponse = ();

	type GetResponse = ();

	type PostBody = serde::de::IgnoredAny;
	type PostResponse = ();
	fn post(self, _body: Option<Self::PostBody>) -> http_common::server::RouteResponse<Option<Self::PostResponse>> {
		Box::pin(async move {
			let mut inner = self.inner.lock().await;
			let inner = &mut *inner;

			let user = aziot_identityd::auth::Uid(0);
			let auth_id = match inner.authenticator.authenticate(user) {
				Ok(auth_id) => auth_id,
				Err(err) => return Err(super::to_http_error(&err)),
			};

			//TODO: get uid from UDS
			match inner.reprovision_device(auth_id).await {
				Ok(()) => (),
				Err(err) => return Err(super::to_http_error(&err)),
			};

			Ok((hyper::StatusCode::NO_CONTENT, None))
		})
	}

	type PutBody = serde::de::IgnoredAny;
	type PutResponse = ();
}
