// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
    user: libc::uid_t,
}

#[async_trait::async_trait]
impl http_common::server::Route for Route {
    type ApiVersion = aziot_key_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_key_common_http::ApiVersion::V2020_09_01)..)
    }

    type Service = super::Service;
    fn from_uri(
        service: &Self::Service,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
        extensions: &http::Extensions,
    ) -> Option<Self> {
        if path != "/key" {
            return None;
        }

        let uid = extensions.get::<libc::uid_t>().copied()?;

        Some(Route {
            api: service.api.clone(),
            user: uid,
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    type DeleteResponse = ();

    type GetResponse = ();

    type PostBody = aziot_key_common_http::create_key_if_not_exists::Request;
    type PostResponse = aziot_key_common_http::create_key_if_not_exists::Response;
    async fn post(
        self,
        body: Option<Self::PostBody>,
    ) -> http_common::server::RouteResponse<Option<Self::PostResponse>> {
        let body = body.ok_or_else(|| http_common::server::Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "missing request body".into(),
        })?;

        let create_key_value = body.import_key_bytes.map_or(
            aziot_key_common::CreateKeyValue::Generate,
            |import_key_bytes| aziot_key_common::CreateKeyValue::Import {
                bytes: import_key_bytes.0,
            },
        );

        let mut api = self.api.lock().await;
        let api = &mut *api;

        let handle = match api.create_key_if_not_exists(
            &body.id,
            create_key_value,
            &body.usage,
            self.user,
        ) {
            Ok(handle) => handle,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let res = aziot_key_common_http::create_key_if_not_exists::Response { handle };
        Ok((hyper::StatusCode::OK, Some(res)))
    }

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = ();
}
