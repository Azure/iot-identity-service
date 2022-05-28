// Copyright (c) Microsoft. All rights reserved.

use http_common::server::RouteResponse;

use crate::error::{Error, InternalError};

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
        if path != "/get_tpm_keys" {
            return None;
        }

        Some(Route {
            api: server.api.clone(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;

    async fn get(self) -> RouteResponse {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        let (endorsement_key, storage_root_key) = api
            .get_tpm_keys()
            .map_err(|e| super::to_http_error(&Error::Internal(InternalError::GetTpmKeys(e))))?;

        let res = aziot_tpm_common_http::get_tpm_keys::Response {
            /// The TPM's Endorsement Key
            endorsement_key: http_common::ByteString(endorsement_key),
            /// The TPM's Storage Root Key
            storage_root_key: http_common::ByteString(storage_root_key),
        };

        let res = http_common::server::response::json(hyper::StatusCode::OK, &res);
        Ok(res)
    }

    type PostBody = serde::de::IgnoredAny;

    type PutBody = serde::de::IgnoredAny;
}
