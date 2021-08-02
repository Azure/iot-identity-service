// Copyright (c) Microsoft. All rights reserved.

lazy_static::lazy_static! {
    static ref URI_REGEX: regex::Regex =
        regex::Regex::new("^/identities/modules/(?P<moduleId>[^/]+)$")
        .expect("hard-coded regex must compile");
}

pub(super) struct Route {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
    module_id: String,
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
        let captures = URI_REGEX.captures(path)?;

        let module_id = &captures["moduleId"];
        let module_id = percent_encoding::percent_decode_str(module_id)
            .decode_utf8()
            .ok()?;

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
            module_id: module_id.into_owned(),
            id_type,
            user: aziot_identityd_config::Uid(uid),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    async fn delete(
        self,
        _body: Option<Self::DeleteBody>,
    ) -> http_common::server::RouteResponse {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        let auth_id = match api.authenticator.authenticate(self.user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        match api
            .delete_identity(auth_id, self.id_type.as_deref(), &self.module_id)
            .await
        {
            Ok(()) => (),
            Err(err) => return Err(super::to_http_error(&err)),
        }

        Ok(http_common::server::empty_response())
    }

    async fn get(self) -> http_common::server::RouteResponse {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        let auth_id = match api.authenticator.authenticate(self.user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let identity = match api
            .get_identity(auth_id, self.id_type.as_deref(), &self.module_id)
            .await
        {
            Ok(v) => v,
            Err(err) => return Err(super::to_http_error(&err)),
        };
        let res = aziot_identity_common_http::get_module_identity::Response { identity };
        let res = http_common::server::json_response(hyper::StatusCode::OK, &res);
        Ok(res)
    }

    type PostBody = serde::de::IgnoredAny;

    type PutBody = serde::de::IgnoredAny;
    // clippy fires this lint for the `_body` parameter of the inner fn in the `async-trait` expansion.
    // It's not clear why clippy does this, especially since it doesn't raise it for other functions
    // that also ignore their `_body` parameter like `fn delete` above.
    //
    // So suppress it manually.
    #[allow(clippy::needless_pass_by_value)]
    async fn put(
        self,
        _body: Self::PutBody,
    ) -> http_common::server::RouteResponse {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        let auth_id = match api.authenticator.authenticate(self.user) {
            Ok(auth_id) => auth_id,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let identity = match api
            .update_identity(auth_id, self.id_type.as_deref(), &self.module_id)
            .await
        {
            Ok(v) => v,
            Err(err) => return Err(super::to_http_error(&err)),
        };
        let res = aziot_identity_common_http::update_module_identity::Response { identity };
        let res = http_common::server::json_response(hyper::StatusCode::OK, &res);
        Ok(res)
    }
}
