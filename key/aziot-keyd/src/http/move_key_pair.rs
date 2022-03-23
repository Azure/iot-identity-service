// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
    user: libc::uid_t,
}

#[async_trait::async_trait]
impl http_common::server::Route for Route {
    type ApiVersion = aziot_key_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_key_common_http::ApiVersion::V2021_05_01)..)
    }

    type Service = super::Service;
    fn from_uri(
        service: &Self::Service,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
        extensions: &http::Extensions,
    ) -> Option<Self> {
        if path != "/keypair/move" {
            return None;
        }

        let uid = extensions.get::<libc::uid_t>().copied()?;

        Some(Route {
            api: service.api.clone(),
            user: uid,
        })
    }

    type DeleteBody = serde::de::IgnoredAny;

    type PostBody = aziot_key_common_http::move_key_pair::Request;
    async fn post(self, body: Option<Self::PostBody>) -> http_common::server::RouteResponse {
        let body = body.ok_or_else(|| http_common::server::Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "missing request body".into(),
        })?;

        let mut api = self.api.lock().await;

        if let Err(err) = api.move_key_pair(&body.from, &body.to, self.user) {
            Err(super::to_http_error(&err))
        } else {
            Ok(http_common::server::response::no_content())
        }
    }

    type PutBody = serde::de::IgnoredAny;
}
