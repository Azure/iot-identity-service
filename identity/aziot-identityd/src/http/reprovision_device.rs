// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
    user: aziot_identityd_config::Credentials,
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
        extensions: &http::Extensions,
    ) -> Option<Self> {
        if path != "/identities/device/reprovision" {
            return None;
        }

        let uid = extensions.get::<libc::uid_t>().cloned()?;

        Some(Route {
            api: service.api.clone(),
            user: aziot_identityd_config::Uid(uid),
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

        let auth_id = match api.authenticator.authenticate(self.user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        match api
            .reprovision_device(auth_id, crate::ReprovisionTrigger::Api)
            .await
        {
            Ok(()) => (),
            Err(err) => return Err(super::to_http_error(&err)),
        };

        Ok((hyper::StatusCode::NO_CONTENT, None))
    }

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = ();
}
