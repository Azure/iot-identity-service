// Copyright (c) Microsoft. All rights reserved.

lazy_static::lazy_static! {
    static ref URI_REGEX: regex::Regex =
        regex::Regex::new("^/(?P<type>(key|keypair))/(?P<keyId>[^/]+)$")
        .expect("hard-coded regex must compile");
}

pub(super) struct Route {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
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
    type DeleteResponse = ();

    type GetResponse = aziot_key_common_http::load::Response;
    async fn get(self) -> http_common::server::RouteResponse<Self::GetResponse> {
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
                    message: format!("invalid type {:?}", type_).into(),
                })
            }
        };

        let res = aziot_key_common_http::load::Response { handle };
        Ok((hyper::StatusCode::OK, res))
    }

    type PostBody = serde::de::IgnoredAny;
    type PostResponse = ();

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = ();
}
