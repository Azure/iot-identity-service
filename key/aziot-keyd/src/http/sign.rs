// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
}

#[async_trait::async_trait]
impl http_common::server::Route for Route {
    type ApiVersion = aziot_key_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_key_common_http::ApiVersion::V2020_09_01)..)
    }

    type Service = super::Service;
    fn from_uri(
        service: &Self::Service,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
        _extensions: &http::Extensions,
    ) -> Option<Self> {
        if path != "/sign" {
            return None;
        }

        Some(Route {
            api: service.api.clone(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;

    type PostBody = aziot_key_common_http::sign::Request;
    async fn post(self, body: Option<Self::PostBody>) -> http_common::server::RouteResponse {
        let body = body.ok_or_else(|| http_common::server::Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "missing request body".into(),
        })?;

        let (mechanism, digest) = match body.parameters {
            aziot_key_common_http::sign::Parameters::Ecdsa { digest } => {
                (aziot_key_common::SignMechanism::Ecdsa, digest)
            }

            aziot_key_common_http::sign::Parameters::HmacSha256 { message } => {
                (aziot_key_common::SignMechanism::HmacSha256, message)
            }
        };

        let mut api = self.api.lock().await;
        let api = &mut *api;

        let signature = match api.sign(&body.key_handle, mechanism, &digest.0) {
            Ok(signature) => signature,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let res = aziot_key_common_http::sign::Response {
            signature: http_common::ByteString(signature),
        };
        let res = http_common::server::response::json(hyper::StatusCode::OK, &res);
        Ok(res)
    }

    type PutBody = serde::de::IgnoredAny;
}
