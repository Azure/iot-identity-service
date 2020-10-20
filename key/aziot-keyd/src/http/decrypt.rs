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
        if path != "/decrypt" {
            return None;
        }

        Some(Route {
            inner: server.inner.clone(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    type DeleteResponse = ();

    type GetResponse = ();

    type PostBody = aziot_key_common_http::decrypt::Request;
    type PostResponse = aziot_key_common_http::decrypt::Response;
    async fn post(
        self,
        body: Option<Self::PostBody>,
    ) -> http_common::server::RouteResponse<Option<Self::PostResponse>> {
        let body = body.ok_or_else(|| http_common::server::Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "missing request body".into(),
        })?;

        let mechanism = match body.parameters {
            aziot_key_common_http::encrypt::Parameters::Aead { iv, aad } => {
                aziot_key_common::EncryptMechanism::Aead {
                    iv: iv.0,
                    aad: aad.0,
                }
            }

            aziot_key_common_http::encrypt::Parameters::RsaPkcs1 => {
                aziot_key_common::EncryptMechanism::RsaPkcs1
            }

            aziot_key_common_http::encrypt::Parameters::RsaNoPadding => {
                aziot_key_common::EncryptMechanism::RsaNoPadding
            }
        };

        let mut inner = self.inner.lock().await;
        let inner = &mut *inner;

        let plaintext = match inner.decrypt(&body.key_handle, mechanism, &body.ciphertext.0) {
            Ok(plaintext) => plaintext,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let res = aziot_key_common_http::decrypt::Response {
            plaintext: http_common::ByteString(plaintext),
        };
        Ok((hyper::StatusCode::OK, Some(res)))
    }

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = ();
}
