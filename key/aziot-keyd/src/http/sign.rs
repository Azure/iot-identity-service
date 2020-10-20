// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
    inner: std::sync::Arc<futures_util::lock::Mutex<aziot_keyd::Server>>,
}

#[async_trait::async_trait]
impl http_common::server::Route for Route {
    type ApiVersion = aziot_key_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_key_common_http::ApiVersion::V2020_09_01)..)
    }

    type Server = super::Server;
    fn from_uri(
        server: &Self::Server,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    ) -> Option<Self> {
        if path != "/sign" {
            return None;
        }

        Some(Route {
            inner: server.inner.clone(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    type DeleteResponse = ();

    type GetResponse = ();

    type PostBody = aziot_key_common_http::sign::Request;
    type PostResponse = aziot_key_common_http::sign::Response;
    async fn post(
        self,
        body: Option<Self::PostBody>,
    ) -> http_common::server::RouteResponse<Option<Self::PostResponse>> {
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

        let mut inner = self.inner.lock().await;
        let inner = &mut *inner;

        let signature = match inner.sign(&body.key_handle, mechanism, &digest.0) {
            Ok(signature) => signature,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let res = aziot_key_common_http::sign::Response {
            signature: http_common::ByteString(signature),
        };
        Ok((hyper::StatusCode::OK, Some(res)))
    }

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = ();
}
