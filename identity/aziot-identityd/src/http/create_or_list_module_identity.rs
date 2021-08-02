// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
    id_type: Option<String>,
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
        query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
        extensions: &http::Extensions,
    ) -> Option<Self> {
        if path != "/identities/modules" {
            return None;
        }

        let id_type: Option<String> = query.iter().find_map(|q| {
            if q.0 == "type" {
                Some(q.1.to_string())
            } else {
                None
            }
        });

        let uid = extensions.get::<libc::uid_t>().cloned()?;

        Some(Route {
            api: service.api.clone(),
            id_type,
            user: aziot_identityd_config::Uid(uid),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;

    async fn get(self) -> http_common::server::RouteResponse {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        let auth_id = match api.authenticator.authenticate(self.user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let identities = match api.get_identities(auth_id, self.id_type.as_deref()).await {
            Ok(v) => v,
            Err(err) => return Err(super::to_http_error(&err)),
        };
        let res = aziot_identity_common_http::get_module_identities::Response { identities };
        let res = http_common::server::json_response(hyper::StatusCode::OK, &res);
        Ok(res)
    }

    type PostBody = aziot_identity_common_http::create_module_identity::Request;
    async fn post(
        self,
        body: Option<Self::PostBody>,
    ) -> http_common::server::RouteResponse {
        let body = body.ok_or_else(|| http_common::server::Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "missing request body".into(),
        })?;

        let mut api = self.api.lock().await;
        let api = &mut *api;

        let auth_id = match api.authenticator.authenticate(self.user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let identity = match api
            .create_identity(auth_id, Some(&body.id_type), &body.module_id, body.opts)
            .await
        {
            Ok(id) => id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let res = aziot_identity_common_http::create_module_identity::Response { identity };
        let res = http_common::server::json_response(hyper::StatusCode::OK, &res);
        Ok(res)
    }

    type PutBody = serde::de::IgnoredAny;
}
