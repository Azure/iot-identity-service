// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
    inner: std::sync::Arc<futures_util::lock::Mutex<aziot_identityd::Server>>,
}

#[async_trait::async_trait]
impl http_common::server::Route for Route {
    type ApiVersion = aziot_identity_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_identity_common_http::ApiVersion::V2020_09_01)..)
    }

    type Server = super::Server;
    fn from_uri(
        server: &Self::Server,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    ) -> Option<Self> {
        if path != "/identities/modules" {
            return None;
        }

        Some(Route {
            inner: server.inner.clone(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    type DeleteResponse = ();

    type GetResponse = aziot_identity_common_http::get_module_identities::Response;
    async fn get(self) -> http_common::server::RouteResponse<Self::GetResponse> {
        let mut inner = self.inner.lock().await;
        let inner = &mut *inner;

        let user = aziot_identityd::auth::Uid(0);
        let auth_id = match inner.authenticator.authenticate(user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        //TODO: get uid from UDS
        let identities = match inner.get_identities(auth_id, "aziot").await {
            Ok(v) => v,
            Err(err) => return Err(super::to_http_error(&err)),
        };
        let res = aziot_identity_common_http::get_module_identities::Response { identities };
        Ok((hyper::StatusCode::OK, res))
    }

    type PostBody = aziot_identity_common_http::create_module_identity::Request;
    type PostResponse = aziot_identity_common_http::create_module_identity::Response;
    async fn post(
        self,
        body: Option<Self::PostBody>,
    ) -> http_common::server::RouteResponse<Option<Self::PostResponse>> {
        let body = body.ok_or_else(|| http_common::server::Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "missing request body".into(),
        })?;

        let mut inner = self.inner.lock().await;
        let inner = &mut *inner;

        let user = aziot_identityd::auth::Uid(0);
        let auth_id = match inner.authenticator.authenticate(user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        //TODO: get uid from UDS
        let identity = match inner
            .create_identity(auth_id, &body.id_type, &body.module_id)
            .await
        {
            Ok(id) => id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let res = aziot_identity_common_http::create_module_identity::Response { identity };
        Ok((hyper::StatusCode::OK, Some(res)))
    }

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = ();
}
