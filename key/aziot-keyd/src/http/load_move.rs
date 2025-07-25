// Copyright (c) Microsoft. All rights reserved.

static URI_REGEX: http_common::EndpointRegex = http_common::EndpointRegex::new(|| {
    regex::Regex::new("^/(?P<type>(key|keypair))/(?P<keyId>[^/]+)$")
        .expect("hard-coded regex must compile")
});

pub(super) struct Route {
    api: std::sync::Arc<tokio::sync::Mutex<crate::Api>>,
    type_: String,
    key_id: String,
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
        let captures = URI_REGEX.captures(path)?;

        let type_ = &captures["type"];
        let type_ = percent_encoding::percent_decode_str(type_)
            .decode_utf8()
            .ok()?;

        let key_id = &captures["keyId"];
        let key_id = percent_encoding::percent_decode_str(key_id)
            .decode_utf8()
            .ok()?;

        let uid = extensions.get::<libc::uid_t>().copied()?;

        Some(Route {
            api: service.api.clone(),
            type_: type_.into_owned(),
            key_id: key_id.into_owned(),
            user: uid,
        })
    }

    type DeleteBody = serde::de::IgnoredAny;

    async fn get(self) -> http_common::server::RouteResponse {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        let handle = match &*self.type_ {
            "keypair" => match api.load_key_pair(&self.key_id, self.user) {
                Ok(handle) => handle,
                Err(err) => return Err(super::to_http_error(&err)),
            },
            "key" => match api.load_key(&self.key_id, self.user) {
                Ok(handle) => handle,
                Err(err) => return Err(super::to_http_error(&err)),
            },
            type_ => {
                return Err(http_common::server::Error {
                    status_code: hyper::StatusCode::BAD_REQUEST,
                    message: format!("invalid type {type_:?}").into(),
                })
            }
        };

        let res = aziot_key_common_http::load::Response { handle };
        let res = http_common::server::response::json(hyper::StatusCode::OK, &res);
        Ok(res)
    }

    type PostBody = aziot_key_common_http::r#move::Request;
    async fn post(self, body: Option<Self::PostBody>) -> http_common::server::RouteResponse {
        let body = body.ok_or_else(|| http_common::server::Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "missing request body".into(),
        })?;

        if body.from == self.key_id {
            return Err(http_common::server::Error {
                status_code: hyper::StatusCode::BAD_REQUEST,
                message: "source and destination for move are identical".into(),
            });
        }

        let mut api = self.api.lock().await;

        if &self.type_ != "keypair" {
            return Err(http_common::server::Error {
                status_code: hyper::StatusCode::BAD_REQUEST,
                message: format!("invalid type {:?}", self.type_).into(),
            });
        }

        if let Err(err) = api.move_key_pair(&body.from, &self.key_id, self.user) {
            Err(super::to_http_error(&err))
        } else {
            Ok(http_common::server::response::no_content())
        }
    }

    type PutBody = serde::de::IgnoredAny;
}
