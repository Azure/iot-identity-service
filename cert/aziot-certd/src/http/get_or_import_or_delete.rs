// Copyright (c) Microsoft. All rights reserved.

lazy_static::lazy_static! {
    static ref URI_REGEX: regex::Regex =
        regex::Regex::new("^/certificates/(?P<certId>[^/]+)$")
        .expect("hard-coded regex must compile");
}

pub(super) struct Route {
    api: std::sync::Arc<tokio::sync::Mutex<crate::Api>>,
    cert_id: String,
    user: libc::uid_t,
}

#[async_trait::async_trait]
impl http_common::server::Route for Route {
    type ApiVersion = aziot_cert_common_http::ApiVersion;
    fn api_version() -> &'static dyn http_common::DynRangeBounds<Self::ApiVersion> {
        &((aziot_cert_common_http::ApiVersion::V2020_09_01)..)
    }

    type Service = super::Service;
    fn from_uri(
        service: &Self::Service,
        path: &str,
        _query: &[(std::borrow::Cow<'_, str>, std::borrow::Cow<'_, str>)],
        extensions: &http::Extensions,
    ) -> Option<Self> {
        let captures = URI_REGEX.captures(path)?;

        let cert_id = &captures["certId"];
        let cert_id = percent_encoding::percent_decode_str(cert_id)
            .decode_utf8()
            .ok()?;

        let uid = extensions.get::<libc::uid_t>().copied()?;

        Some(Route {
            api: service.api.clone(),
            cert_id: cert_id.into_owned(),
            user: uid,
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    async fn delete(self, _body: Option<Self::DeleteBody>) -> http_common::server::RouteResponse {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        if let Err(err) = api.delete_cert(&self.cert_id, self.user) {
            return Err(super::to_http_error(&err));
        }

        Ok(http_common::server::response::no_content())
    }

    async fn get(self) -> http_common::server::RouteResponse {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        let pem = api.get_cert(&self.cert_id);
        let pem = match pem {
            Ok(pem) => pem,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let res = aziot_cert_common_http::get_cert::Response {
            pem: aziot_cert_common_http::Pem(pem),
        };
        let res = http_common::server::response::json(hyper::StatusCode::OK, &res);
        Ok(res)
    }

    type PostBody = serde::de::IgnoredAny;

    type PutBody = aziot_cert_common_http::import_cert::Request;
    async fn put(self, body: Self::PutBody) -> http_common::server::RouteResponse {
        let mut api = self.api.lock().await;
        let api = &mut *api;

        match api.import_cert(&self.cert_id, &body.pem.0, self.user) {
            Ok(()) => (),
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let res = aziot_cert_common_http::import_cert::Response { pem: body.pem };
        let res = http_common::server::response::json(hyper::StatusCode::CREATED, &res);
        Ok(res)
    }
}
