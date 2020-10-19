// Copyright (c) Microsoft. All rights reserved.

use http_common::server::RouteResponse;

pub(super) struct Route {
    inner: std::sync::Arc<futures_util::lock::Mutex<aziot_tpmd::Server>>,
}

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
        if path != "/get_tpm_keys" {
            return None;
        }

        Some(Route {
            inner: server.inner.clone(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    type DeleteResponse = ();

    type GetResponse = aziot_tpm_common_http::get_tpm_keys::Response;
    fn get(self) -> RouteResponse<Self::GetResponse> {
        Box::pin(async move {
            let mut inner = self.inner.lock().await;
            let inner = &mut *inner;

            let keys = inner.get_tpm_keys().map_err(|e| super::to_http_error(&e))?;

            let res = aziot_tpm_common_http::get_tpm_keys::Response {
                /// The TPM's Endorsement Key
                endorsement_key: http_common::ByteString(keys.endorsement_key),
                /// The TPM's Storage Root Key
                storage_root_key: http_common::ByteString(keys.storage_root_key),
            };
            Ok((hyper::StatusCode::OK, res))
        })
    }

    type PostBody = serde::de::IgnoredAny;
    type PostResponse = ();

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = ();
}
