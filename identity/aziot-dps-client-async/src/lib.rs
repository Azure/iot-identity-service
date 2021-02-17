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

/// This is the interval at which to poll DPS for registration assignment status
const DPS_ASSIGNMENT_RETRY_INTERVAL_SECS: u64 = 10;

/// This is the number of seconds to wait for DPS to complete assignment to a hub
const DPS_ASSIGNMENT_TIMEOUT_SECS: u64 = 120;

pub const DPS_ENCODE_SET: &percent_encoding::AsciiSet =
    &http_common::PATH_SEGMENT_ENCODE_SET.add(b'=');

#[derive(Clone)]
pub enum DpsAuthKind {
    SymmetricKey {
        sas_key: String,
    },
    X509 {
        identity_cert: String,
        identity_pk: String,
    },
    Tpm,
    /// Used as part of a recursive call within `request`
    #[doc(hidden)]
    TpmWithAuth {
        // base64 encoded
        auth_key: String,
    },
}

pub struct Client {
    global_endpoint: String,
    scope_id: String,

    key_client: Arc<aziot_key_client_async::Client>,
    key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
    cert_client: Arc<aziot_cert_client_async::Client>,
    tpm_client: Arc<aziot_tpm_client_async::Client>,
    proxy_uri: Option<hyper::Uri>,
}

impl Client {
    #[must_use]
    pub fn new(
        global_endpoint: &str,
        scope_id: &str,
        key_client: Arc<aziot_key_client_async::Client>,
        key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
        cert_client: Arc<aziot_cert_client_async::Client>,
        tpm_client: Arc<aziot_tpm_client_async::Client>,
        proxy_uri: Option<hyper::Uri>,
    ) -> Self {
        Client {
            global_endpoint: global_endpoint.to_owned(),
            scope_id: scope_id.to_owned(),

            key_client,
            key_engine,
            cert_client,
            tpm_client,
            proxy_uri,
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

        let body = match auth_kind {
            DpsAuthKind::Tpm => {
                let aziot_tpm_common::TpmKeys {
                    endorsement_key,
                    storage_root_key,
                } = self.tpm_client.get_tpm_keys().await?;

                model::DeviceRegistration {
                    registration_id: Some(registration_id.into()),
                    tpm: Some(model::TpmAttestation {
                        endorsement_key: base64::encode(&endorsement_key),
                        storage_root_key: base64::encode(&storage_root_key),
                    }),
                }
            }
            _ => model::DeviceRegistration {
                registration_id: Some(registration_id.into()),
                tpm: None,
            },
        };

        let mut auth_kind = auth_kind.clone();

        // kick off the registration
        let res: model::RegistrationOperationStatus = self
            .request(
                registration_id,
                http::Method::PUT,
                &resource_uri,
                &mut auth_kind,
                Some(&body),
            )
            .await?;

        // spin until the registration has completed successfully
        let resource_uri = format!(
            "/{}/registrations/{}/operations/{}?api-version=2018-11-01",
            self.scope_id, registration_id, res.operation_id
        );

        let mut retry_count =
            (DPS_ASSIGNMENT_TIMEOUT_SECS / DPS_ASSIGNMENT_RETRY_INTERVAL_SECS) + 1;
        let res = loop {
            if retry_count == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "exceeded DPS assignment timeout threshold",
                ));
            }
            retry_count -= 1;

            let res: model::RegistrationOperationStatus = self
                .request::<(), _>(
                    registration_id,
                    http::Method::GET,
                    &resource_uri,
                    &mut auth_kind,
                    None,
                )
                .await?;

            if !res.status.eq_ignore_ascii_case("assigning") {
                break res;
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(
                DPS_ASSIGNMENT_RETRY_INTERVAL_SECS,
            ))
            .await;
        };

        if matches!(auth_kind, DpsAuthKind::TpmWithAuth { .. }) {
            // import the returned authentication key into the TPM
            let auth_key = res
                .registration_state
                .as_ref()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, "malformed DPS server response")
                })?
                .tpm
                .as_ref()
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Other, "malformed DPS server response")
                })?
                .authentication_key
                .clone();

            self.tpm_client
                .import_auth_key(
                    base64::decode(auth_key)
                        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?,
                )
                .await?;
        }

        Ok(res)
    }

    // TPM provisioning has special 2-step challenge/response flow which is
    // basically identical to the symmetric key flow, except that the TPM client
    // is used instead of the key client. To keep things DRY, a recursive call
    // is used, passing `DpsAuthKind::TpmWithAuth` as the auth kind.
    #[async_recursion::async_recursion]
    async fn request<TRequest, TResponse>(
        &self,
        registration_id: &str,
        method: http::Method,
        resource_uri: &str,
        auth_kind: &mut DpsAuthKind,
        orig_body: Option<TRequest>,
    ) -> std::io::Result<TResponse>
    where
        TRequest: serde::Serialize + Send,
        TResponse: serde::de::DeserializeOwned,
    {
        let uri = format!("{}{}", self.global_endpoint, resource_uri);

        let req = hyper::Request::builder().method(&method).uri(&uri);
        // `req` is consumed by both branches, so this cannot be replaced with `Option::map_or_else`
        //
        // Ref: https://github.com/rust-lang/rust-clippy/issues/5822
        #[allow(clippy::option_if_let_else)]
        let req = if let Some(ref body) = orig_body {
            let body = serde_json::to_vec(&body)
                .expect("serializing request body to JSON cannot fail")
                .into();
            req.header(hyper::header::CONTENT_TYPE, "application/json")
                .body(body)
        } else {
            req.body(hyper::Body::default())
        };

        let mut req = req.expect("cannot fail to create hyper request");

        let connector = match &auth_kind {
            DpsAuthKind::Tpm => {
                http_common::MaybeProxyConnector::new(self.proxy_uri.clone(), None)?
            }
            DpsAuthKind::SymmetricKey { sas_key: key }
            | DpsAuthKind::TpmWithAuth { auth_key: key } => {
                let audience = format!("{}/registrations/{}", self.scope_id, registration_id);
                let (connector, token) = if matches!(auth_kind, DpsAuthKind::SymmetricKey { .. }) {
                    get_sas_connector(
                        &audience,
                        &key,
                        &*self.key_client,
                        self.proxy_uri.clone(),
                        false,
                    )
                    .await?
                } else {
                    get_sas_connector(
                        &audience,
                        &base64::decode(key)
                            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?,
                        &*self.tpm_client,
                        self.proxy_uri.clone(),
                        true,
                    )
                    .await?
                };

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
                    self.proxy_uri.clone(),
                )
                .await?
            }
        };

        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().build(connector);
        log::debug!("DPS request {:?}", req);

        let res = client
            .request(req)
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        let (
            http::response::Parts {
                status, headers, ..
            },
            body,
        ) = res.into_parts();
        log::debug!("DPS response status {:?}", status);
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

        let res: TResponse = match status {
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

            status if status.is_client_error() && matches!(auth_kind, DpsAuthKind::Tpm) => {
                if !is_json {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "malformed HTTP response",
                    ));
                }
                let reg_result: model::TpmRegistrationResult = serde_json::from_slice(&body)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

                // update auth method
                *auth_kind = DpsAuthKind::TpmWithAuth {
                    auth_key: reg_result.authentication_key,
                };

                return self
                    .request(registration_id, method, resource_uri, auth_kind, orig_body)
                    .await;
            }

            status if status.is_client_error() || status.is_server_error() => {
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
