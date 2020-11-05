// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_and_return,
    clippy::let_unit_value,
    clippy::missing_errors_doc,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity
)]

use std::sync::Arc;

use aziot_cloud_client_async_common::{get_sas_connector, get_x509_connector};

pub mod model;

pub const DPS_ENCODE_SET: &percent_encoding::AsciiSet =
    &http_common::PATH_SEGMENT_ENCODE_SET.add(b'=');

pub enum DpsAuthKind {
    SymmetricKey {
        sas_key: String,
    },
    X509 {
        identity_cert: String,
        identity_pk: String,
    },
}

pub struct Client {
    global_endpoint: String,
    scope_id: String,

    key_client: Arc<aziot_key_client_async::Client>,
    key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
    cert_client: Arc<aziot_cert_client_async::Client>,
}

impl Client {
    #[must_use]
    pub fn new(
        global_endpoint: &str,
        scope_id: &str,
        key_client: Arc<aziot_key_client_async::Client>,
        key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
        cert_client: Arc<aziot_cert_client_async::Client>,
    ) -> Self {
        Client {
            global_endpoint: global_endpoint.to_owned(),
            scope_id: scope_id.to_owned(),

            key_client,
            key_engine,
            cert_client,
        }
    }

    pub async fn register(
        &self,
        registration_id: &str,
        auth_kind: &DpsAuthKind,
    ) -> Result<model::RegistrationOperationStatus, std::io::Error> {
        let resource_uri = format!(
            "/{}/registrations/{}/register?api-version=2018-11-01",
            self.scope_id, registration_id
        );

        let body = model::DeviceRegistration {
            registration_id: Some(registration_id.into()),
        };

        let res: model::RegistrationOperationStatus = self
            .request(
                registration_id,
                http::Method::PUT,
                &resource_uri,
                auth_kind,
                Some(&body),
            )
            .await?;

        Ok(res)
    }

    pub async fn get_operation_status(
        &self,
        registration_id: &str,
        operation_id: &str,
        auth_kind: &DpsAuthKind,
    ) -> Result<model::RegistrationOperationStatus, std::io::Error> {
        let resource_uri = format!(
            "/{}/registrations/{}/operations/{}?api-version=2018-11-01",
            self.scope_id, registration_id, operation_id
        );

        let res: model::RegistrationOperationStatus = self
            .request::<(), _>(
                registration_id,
                http::Method::GET,
                &resource_uri,
                auth_kind,
                None,
            )
            .await?;

        Ok(res)
    }

    async fn request<TRequest, TResponse>(
        &self,
        registration_id: &str,
        method: http::Method,
        resource_uri: &str,
        auth_kind: &DpsAuthKind,
        body: Option<&TRequest>,
    ) -> std::io::Result<TResponse>
    where
        TRequest: serde::Serialize,
        TResponse: serde::de::DeserializeOwned,
    {
        let uri = format!("{}{}", self.global_endpoint, resource_uri);

        let req = hyper::Request::builder().method(method).uri(uri);
        // `req` is consumed by both branches, so this cannot be replaced with `Option::map_or_else`
        //
        // Ref: https://github.com/rust-lang/rust-clippy/issues/5822
        #[allow(clippy::option_if_let_else)]
        let req = if let Some(body) = body {
            let body = serde_json::to_vec(body)
                .expect("serializing request body to JSON cannot fail")
                .into();
            req.header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body)
        } else {
            req.body(hyper::Body::default())
        };

        let mut req = req.expect("cannot fail to create hyper request");

        let connector = match auth_kind {
            DpsAuthKind::SymmetricKey { sas_key } => {
                let audience = format!("{}/registrations/{}", self.scope_id, registration_id);
                let (connector, token) =
                    get_sas_connector(&audience, &sas_key, &self.key_client).await?;

                let authorization_header_value = hyper::header::HeaderValue::from_str(&token)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                req.headers_mut()
                    .append(hyper::header::AUTHORIZATION, authorization_header_value);
                connector
            }
            DpsAuthKind::X509 {
                identity_cert,
                identity_pk,
            } => {
                get_x509_connector(
                    &identity_cert,
                    &identity_pk,
                    &self.key_client,
                    &mut *self.key_engine.lock().await,
                    &self.cert_client,
                )
                .await?
            }
        };

        let client = hyper::Client::builder().build(connector);
        log::debug!("DPS request {:?}", req);

        let res = client
            .request(req)
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        let (
            http::response::Parts {
                status: res_status_code,
                headers,
                ..
            },
            body,
        ) = res.into_parts();
        log::debug!("DPS response status {:?}", res_status_code);
        log::debug!("DPS response headers{:?}", headers);

        let mut is_json = false;
        for (header_name, header_value) in headers {
            if header_name == Some(hyper::header::CONTENT_TYPE) {
                let value = header_value
                    .to_str()
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                if value.contains("application/json") {
                    is_json = true;
                }
            }
        }

        let body = hyper::body::to_bytes(body)
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
        log::debug!("DPS response body {:?}", body);

        let res: TResponse = match res_status_code {
            hyper::StatusCode::OK | hyper::StatusCode::ACCEPTED => {
                if !is_json {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "malformed HTTP response",
                    ));
                }
                let res = serde_json::from_slice(&body)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                res
            }

            res_status_code
                if res_status_code.is_client_error() || res_status_code.is_server_error() =>
            {
                #[derive(Debug, serde::Deserialize, serde::Serialize)]
                pub struct Error {
                    #[serde(alias = "Message")]
                    pub message: std::borrow::Cow<'static, str>,
                }

                let res: Error = serde_json::from_slice(&body)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                return Err(std::io::Error::new(std::io::ErrorKind::Other, res.message));
            }

            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "malformed HTTP response",
                ))
            }
        };

        Ok(res)
    }
}
