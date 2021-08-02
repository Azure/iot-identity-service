// Copyright (c) Microsoft. All rights reserved.

use http_common::server::RouteResponse;

pub(super) struct Route {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
}

#[async_trait::async_trait]
impl http_common::server::Route for Route {
    type ApiVersion = aziot_tpm_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_tpm_common_http::ApiVersion::V2020_09_01)..)
    }

    type Service = super::Service;
    fn from_uri(
        server: &Self::Service,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
        _extensions: &http::Extensions,
    ) -> Option<Self> {
        if path != "/import_auth_key" {
            return None;
        }

        Some(Route {
            api: server.api.clone(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;

    type PostBody = aziot_tpm_common_http::import_auth_key::Request;
    async fn post(self, body: Option<Self::PostBody>) -> RouteResponse {
        let body = body.ok_or_else(|| http_common::server::Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "missing request body".into(),
        })?;

        let mut api = self.api.lock().await;
        let api = &mut *api;

        api.import_auth_key(&body.key.0)
            .map_err(|e| super::to_http_error(&e))?;

        let res = aziot_tpm_common_http::import_auth_key::Response {};
        let res = http_common::server::json_response(hyper::StatusCode::OK, &res);
        Ok(res)
    }

    type PutBody = serde::de::IgnoredAny;
}
