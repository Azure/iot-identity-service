// Copyright (c) Microsoft. All rights reserved.

use http_common::server::RouteResponse;

pub(super) struct Route {
    inner: std::sync::Arc<futures_util::lock::Mutex<aziot_tpmd::Server>>,
}

#[async_trait::async_trait]
impl http_common::server::Route for Route {
    type ApiVersion = aziot_tpm_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_tpm_common_http::ApiVersion::V2020_10_15)..)
    }

    type Server = super::Server;
    fn from_uri(
        server: &Self::Server,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    ) -> Option<Self> {
        if path != "/sign_with_auth_key" {
            return None;
        }

        Some(Route {
            inner: server.inner.clone(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    type DeleteResponse = ();

    type GetResponse = ();

    type PostBody = aziot_tpm_common_http::sign_with_auth_key::Request;
    type PostResponse = aziot_tpm_common_http::sign_with_auth_key::Response;
    async fn post(self, body: Option<Self::PostBody>) -> RouteResponse<Option<Self::PostResponse>> {
        let body = body.ok_or_else(|| http_common::server::Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "missing request body".into(),
        })?;

        let mut inner = self.inner.lock().await;
        let inner = &mut *inner;

        let digest = inner
            .sign_with_auth_key(&body.data.0)
            .map_err(|e| super::to_http_error(&e))?;

        let res = aziot_tpm_common_http::sign_with_auth_key::Response {
            digest: http_common::ByteString(digest),
        };
        Ok((hyper::StatusCode::OK, Some(res)))
    }

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = ();
}
