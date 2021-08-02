// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
    user: aziot_identityd_config::Credentials,
}

#[async_trait::async_trait]
impl http_common::server::Route for Route {
    type ApiVersion = aziot_identity_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_identity_common_http::ApiVersion::V2020_09_01)..)
    }

    type Service = super::Service;
    fn from_uri(
        service: &Self::Service,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
        extensions: &http::Extensions,
    ) -> Option<Self> {
        if path != "/trust-bundle" {
            return None;
        }

        let uid = extensions.get::<libc::uid_t>().cloned()?;

        Some(Route {
            api: service.api.clone(),
            user: aziot_identityd_config::Uid(uid),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;

    async fn get(self) -> http_common::server::RouteResponse {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        let auth_id = match api.authenticator.authenticate(self.user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let certificate = match api.get_trust_bundle(auth_id).await {
            Ok(v) => v,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let res = aziot_identity_common_http::get_trust_bundle::Response { certificate };
        let res = http_common::server::response::json(hyper::StatusCode::OK, &res);
        Ok(res)
    }

    type PostBody = serde::de::IgnoredAny;

    type PutBody = serde::de::IgnoredAny;
}
