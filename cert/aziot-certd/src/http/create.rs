// Copyright (c) Microsoft. All rights reserved.

pub(super) struct Route {
    api: std::sync::Arc<futures_util::lock::Mutex<crate::Api>>,
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
        if path != "/certificates" {
            return None;
        }

        let uid = extensions.get::<libc::uid_t>().cloned()?;

        Some(Route {
            api: service.api.clone(),
            user: uid,
        })
    }

    type DeleteBody = serde::de::IgnoredAny;
    type DeleteResponse = ();

    type GetResponse = ();

    type PostBody = aziot_cert_common_http::create_cert::Request;
    type PostResponse = aziot_cert_common_http::create_cert::Response;
    async fn post(
        self,
        body: Option<Self::PostBody>,
    ) -> http_common::server::RouteResponse<Option<Self::PostResponse>> {
        let body = body.ok_or_else(|| http_common::server::Error {
            status_code: http::StatusCode::BAD_REQUEST,
            message: "missing request body".into(),
        })?;

        let pem = crate::Api::create_cert(
            self.api,
            body.cert_id,
            body.csr.0,
            body.issuer.map(
                |aziot_cert_common_http::create_cert::Issuer {
                     cert_id,
                     private_key_handle,
                 }| (cert_id, private_key_handle),
            ),
            self.user,
        )
        .await;
        let pem = match pem {
            Ok(pem) => pem,
            Err(err) => return Err(super::to_http_error(&err)),
        };

        let res = aziot_cert_common_http::create_cert::Response {
            pem: aziot_cert_common_http::Pem(pem),
        };
        Ok((hyper::StatusCode::CREATED, Some(res)))
    }

    type PutBody = serde::de::IgnoredAny;
    type PutResponse = ();
}
