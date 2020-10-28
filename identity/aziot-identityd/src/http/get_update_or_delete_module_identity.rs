// Copyright (c) Microsoft. All rights reserved.

lazy_static::lazy_static! {
    static ref URI_REGEX: regex::Regex =
        regex::Regex::new("^/identities/modules/(?P<moduleId>[^/]+)$")
        .expect("hard-coded regex must compile");
}

pub(super) struct Route {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
    module_id: String,
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
        let captures = URI_REGEX.captures(path)?;

        let module_id = &captures["moduleId"];
        let module_id = percent_encoding::percent_decode_str(module_id)
            .decode_utf8()
            .ok()?;

        Some(Route {
            api: service.api.clone(),
            module_id: module_id.into_owned(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    type DeleteResponse = ();
    async fn delete(
        self,
        _body: Option<Self::DeleteBody>,
    ) -> http_common::server::RouteResponse<Option<Self::DeleteResponse>> {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        let user = crate::auth::Uid(0);
        let auth_id = match api.authenticator.authenticate(user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        //TODO: get uid from UDS
        match api.delete_identity(auth_id, "aziot", &self.module_id).await {
            Ok(()) => (),
            Err(err) => return Err(super::to_http_error(&err)),
        }

        Ok((hyper::StatusCode::NO_CONTENT, None))
    }

    type GetResponse = aziot_identity_common_http::get_module_identity::Response;
    async fn get(self) -> http_common::server::RouteResponse<Self::GetResponse> {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        let user = crate::auth::Uid(0);
        let auth_id = match api.authenticator.authenticate(user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        //TODO: get uid from UDS
        let identity = match api.get_identity(auth_id, "aziot", &self.module_id).await {
            Ok(v) => v,
            Err(err) => return Err(super::to_http_error(&err)),
        };
        let res = aziot_identity_common_http::get_module_identity::Response { identity };
        Ok((hyper::StatusCode::OK, res))
    }

    type PostBody = serde::de::IgnoredAny;
    type PostResponse = ();

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = aziot_identity_common_http::update_module_identity::Response;
    // clippy fires this lint for the `_body` parameter of the inner fn in the `async-trait` expansion.
    // It's not clear why clippy does this, especially since it doesn't raise it for other functions
    // that also ignore their `_body` parameter like `fn delete` above.
    //
    // So suppress it manually.
    #[allow(clippy::needless_pass_by_value)]
    async fn put(
        self,
        _body: Self::PutBody,
    ) -> http_common::server::RouteResponse<Self::PutResponse> {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        let user = crate::auth::Uid(0);
        let auth_id = match api.authenticator.authenticate(user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let identity = match api.update_identity(auth_id, "aziot", &self.module_id).await {
            Ok(v) => v,
            Err(err) => return Err(super::to_http_error(&err)),
        };
        let res = aziot_identity_common_http::update_module_identity::Response { identity };
        Ok((hyper::StatusCode::OK, res))
    }
}
