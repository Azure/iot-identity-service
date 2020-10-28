// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
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
    ) -> Option<Self> {
        if path != "/identities/device/reprovision" {
            return None;
        }

        Some(Route {
            api: service.api.clone(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    type DeleteResponse = ();

    type GetResponse = ();

    type PostBody = serde::de::IgnoredAny;
    type PostResponse = ();
    async fn post(
        self,
        _body: Option<Self::PostBody>,
    ) -> http_common::server::RouteResponse<Option<Self::PostResponse>> {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        let user = crate::auth::Uid(0);
        let auth_id = match api.authenticator.authenticate(user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        //TODO: get uid from UDS
        match api.reprovision_device(auth_id).await {
            Ok(()) => (),
            Err(err) => return Err(super::to_http_error(&err)),
        };

        Ok((hyper::StatusCode::NO_CONTENT, None))
    }

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = ();
}
