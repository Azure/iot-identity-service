// Copyright (c) Microsoft. All rights reserved.

lazy_static::lazy_static! {
    static ref URI_REGEX: regex::Regex =
        regex::Regex::new("^/parameters/(?P<parameterName>[^/]+)$")
        .expect("hard-coded regex must compile");
}

pub(super) struct Route {
    inner: std::sync::Arc<futures_util::lock::Mutex<aziot_keyd::Server>>,
    parameter_name: String,
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

        let parameter_name = &captures["parameterName"];
        let parameter_name = percent_encoding::percent_decode_str(parameter_name)
            .decode_utf8()
            .ok()?;

        Some(Route {
            inner: server.inner.clone(),
            parameter_name: parameter_name.into_owned(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    type DeleteResponse = ();

    type GetResponse = ();

    type PostBody = aziot_key_common_http::get_key_pair_public_parameter::Request;
    type PostResponse = aziot_key_common_http::get_key_pair_public_parameter::Response;
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

        let parameter_value =
            match inner.get_key_pair_public_parameter(&body.key_handle, &self.parameter_name) {
                Ok(parameter_value) => parameter_value,
                Err(err) => return Err(super::to_http_error(&err)),
            };

        let res = aziot_key_common_http::get_key_pair_public_parameter::Response {
            value: parameter_value,
        };
        Ok((hyper::StatusCode::OK, Some(res)))
    }

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = ();
}
