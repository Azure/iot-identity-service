// Copyright (c) Microsoft. All rights reserved.

lazy_static::lazy_static! {
	static ref URI_REGEX: regex::Regex =
		regex::Regex::new("^/identities/modules/(?P<moduleId>[^/]+)$")
		.expect("hard-coded regex must compile");
}

pub(super) struct Route {
	inner: std::sync::Arc<futures_util::lock::Mutex<aziot_identityd::Server>>,
	module_id: String,
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
		let captures = URI_REGEX.captures(path)?;

		let module_id = &captures["moduleId"];
		let module_id = percent_encoding::percent_decode_str(module_id).decode_utf8().ok()?;

		Some(Route {
			inner: server.inner.clone(),
			module_id: module_id.into_owned(),
		})
	}

	type DeleteBody = serde::de::IgnoredAny;
	type DeleteResponse = ();
	fn delete(self, _body: Option<Self::DeleteBody>) -> http_common::server::RouteResponse<Option<Self::DeleteResponse>> {
		Box::pin(async move {
			let mut inner = self.inner.lock().await;
			let inner = &mut *inner;

			let user = aziot_identityd::auth::Uid(0);
			let auth_id = match inner.authenticator.authenticate(user) {
				Ok(auth_id) => auth_id,
				Err(err) => return Err(super::to_http_error(&err)),
			};

			//TODO: get uid from UDS
			match inner.delete_identity(auth_id, "aziot", &self.module_id).await {
				Ok(()) => (),
				Err(err) => return Err(super::to_http_error(&err)),
			}

			Ok((hyper::StatusCode::NO_CONTENT, None))
		})
	}

	type GetResponse = aziot_identity_common_http::get_module_identity::Response;
	fn get(self) -> http_common::server::RouteResponse<Self::GetResponse> {
		Box::pin(async move {
			let mut inner = self.inner.lock().await;
			let inner = &mut *inner;

			let user = aziot_identityd::auth::Uid(0);
			let auth_id = match inner.authenticator.authenticate(user) {
				Ok(auth_id) => auth_id,
				Err(err) => return Err(super::to_http_error(&err)),
			};

			//TODO: get uid from UDS
			let identity = match inner.get_identity(auth_id, "aziot", &self.module_id).await {
				Ok(v) => v,
				Err(err) => return Err(super::to_http_error(&err)),
			};
			let res = aziot_identity_common_http::get_module_identity::Response {
				identity,
			};
			Ok((hyper::StatusCode::OK, res))
		})
	}

	type PostBody = serde::de::IgnoredAny;
	type PostResponse = ();

	type PutBody = serde::de::IgnoredAny;
	type PutResponse = ();
}
