// Copyright (c) Microsoft. All rights reserved.

lazy_static::lazy_static! {
    static ref URI_REGEX: regex::Regex =
        regex::Regex::new("^/certificates/(?P<certId>[^/]+)$")
        .expect("hard-coded regex must compile");
}

pub(super) struct Route {
    inner: std::sync::Arc<futures_util::lock::Mutex<aziot_certd::Server>>,
    cert_id: String,
}

#[async_trait::async_trait]
impl http_common::server::Route for Route {
    type ApiVersion = aziot_cert_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_cert_common_http::ApiVersion::V2020_09_01)..)
    }

    type Server = super::Server;
    fn from_uri(
        server: &Self::Server,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
    ) -> Option<Self> {
        let captures = URI_REGEX.captures(path)?;

        let cert_id = &captures["certId"];
        let cert_id = percent_encoding::percent_decode_str(cert_id)
            .decode_utf8()
            .ok()?;

        Some(Route {
            inner: server.inner.clone(),
            cert_id: cert_id.into_owned(),
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    type DeleteResponse = ();
    async fn delete(
        self,
        _body: Option<Self::DeleteBody>,
    ) -> http_common::server::RouteResponse<Option<Self::DeleteResponse>> {
        let mut inner = self.inner.lock().await;
        let inner = &mut *inner;

        if let Err(err) = inner.delete_cert(&self.cert_id) {
            return Err(super::to_http_error(&err));
        }

        Ok((hyper::StatusCode::NO_CONTENT, None))
    }

    type GetResponse = aziot_cert_common_http::get_cert::Response;
    async fn get(self) -> http_common::server::RouteResponse<Self::GetResponse> {
        let mut inner = self.inner.lock().await;
        let inner = &mut *inner;

        let pem = inner.get_cert(&self.cert_id);
        let pem = match pem {
            Ok(pem) => pem,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let res = aziot_cert_common_http::get_cert::Response {
            pem: aziot_cert_common_http::Pem(pem),
        };
        Ok((hyper::StatusCode::OK, res))
    }

    type PostBody = serde::de::IgnoredAny;
    type PostResponse = ();

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = ();
}
