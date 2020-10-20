// Copyright (c) Microsoft. All rights reserved.

lazy_static::lazy_static! {
    static ref URI_REGEX: regex::Regex =
        regex::Regex::new("^/(?P<type>(key|keypair))/(?P<keyId>[^/]+)$")
        .expect("hard-coded regex must compile");
}

pub(super) struct Route {
    inner: std::sync::Arc<futures_util::lock::Mutex<aziot_keyd::Server>>,
    type_: String,
    key_id: String,
}

#[async_trait::async_trait]
impl http_common::server::Route for Route {
    type ApiVersion = aziot_key_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_key_common_http::ApiVersion::V2020_09_01)..)
    }

    type Server = super::Server;
    fn from_uri(
        server: &Self::Server,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
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

        Some(Route {
            inner: server.inner.clone(),
            type_: type_.into_owned(),
            key_id: key_id.into_owned(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    type DeleteResponse = ();

    type GetResponse = aziot_key_common_http::load::Response;
    async fn get(self) -> http_common::server::RouteResponse<Self::GetResponse> {
        let mut inner = self.inner.lock().await;
        let inner = &mut *inner;

        let handle = match &*self.type_ {
            "keypair" => match inner.load_key_pair(&self.key_id) {
                Ok(handle) => handle,
                Err(err) => return Err(super::to_http_error(&err)),
            },
            "key" => match inner.load_key(&self.key_id) {
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
