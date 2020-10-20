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
        if path != "/key" {
            return None;
        }

        Some(Route {
            inner: server.inner.clone(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    type DeleteResponse = ();

    type GetResponse = ();

    type PostBody = aziot_key_common_http::create_key_if_not_exists::Request;
    type PostResponse = aziot_key_common_http::create_key_if_not_exists::Response;
    async fn post(
        self,
        body: Option<Self::PostBody>,
    ) -> http_common::server::RouteResponse<Option<Self::PostResponse>> {
        let body = body.ok_or_else(|| http_common::server::Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "missing request body".into(),
        })?;

        let create_key_value = match (body.generate_key_len, body.import_key_bytes) {
            (Some(generate_key_len), None) => aziot_key_common::CreateKeyValue::Generate {
                length: generate_key_len,
            },

            (None, Some(import_key_bytes)) => aziot_key_common::CreateKeyValue::Import {
                bytes: import_key_bytes.0,
            },

            (Some(_), Some(_)) => {
                return Err(http_common::server::Error {
                    status_code: hyper::StatusCode::UNPROCESSABLE_ENTITY,
                    message:
                        "both lengthBytes and keyBytes cannot be specified in the same request"
                            .into(),
                })
            }

            (None, None) => {
                return Err(http_common::server::Error {
                    status_code: hyper::StatusCode::UNPROCESSABLE_ENTITY,
                    message: "one of lengthBytes and keyBytes must be specified in the request"
                        .into(),
                })
            }
        };

        let mut inner = self.inner.lock().await;
        let inner = &mut *inner;

        let handle = match inner.create_key_if_not_exists(&body.id, create_key_value) {
            Ok(handle) => handle,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let res = aziot_key_common_http::create_key_if_not_exists::Response { handle };
        Ok((hyper::StatusCode::OK, Some(res)))
    }

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = ();
}
