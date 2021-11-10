// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
}

#[async_trait::async_trait]
impl http_common::server::Route for Route {
    type ApiVersion = aziot_identity_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_identity_common_http::ApiVersion::V2021_12_01)..)
    }

    type Service = super::Service;
    fn from_uri(
        service: &Self::Service,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
        _extensions: &http::Extensions,
    ) -> Option<Self> {
        if path != "/identities/provisioning" {
            return None;
        }

        Some(Route {
            api: service.api.clone(),
        })
    }

    async fn get(self) -> http_common::server::RouteResponse {
        let provisioning = {
            let api = self.api.lock().await;

            api.settings.provisioning.provisioning.clone()
        };

        let res: aziot_identity_common_http::get_provisioning_info::Response = provisioning.into();
        let res = http_common::server::response::json(hyper::StatusCode::OK, &res);
        Ok(res)
    }

    type DeleteBody = serde::de::IgnoredAny;
    type PostBody = serde::de::IgnoredAny;
    type PutBody = serde::de::IgnoredAny;
}
