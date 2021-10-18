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
    TpmDpsNonce,
}

pub struct Client {
    global_endpoint: url::Url,
    scope_id: String,

    req_timeout: std::time::Duration,
    req_retries: u32,

    key_client: Arc<aziot_key_client_async::Client>,
    key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
    cert_client: Arc<aziot_cert_client_async::Client>,
    tpm_client: Arc<aziot_tpm_client_async::Client>,
    proxy_uri: Option<hyper::Uri>,

    client_cert_key: String,
}

impl Client {
    #[must_use]
    pub fn new(
        global_endpoint: &url::Url,
        scope_id: &str,
        req_timeout: std::time::Duration,
        req_retries: u32,
        key_client: Arc<aziot_key_client_async::Client>,
        key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
        cert_client: Arc<aziot_cert_client_async::Client>,
        tpm_client: Arc<aziot_tpm_client_async::Client>,
        proxy_uri: Option<hyper::Uri>,
        client_cert_key: String,
    ) -> Self {
        Client {
            global_endpoint: global_endpoint.clone(),
            scope_id: scope_id.to_owned(),

            req_timeout,
            req_retries,

            key_client,
            key_engine,
            cert_client,
            tpm_client,
            proxy_uri,

            client_cert_key,
        }
    }

    pub async fn register(
        &self,
        registration_id: &str,
        auth_kind: &DpsAuthKind,
    ) -> Result<model::RegistrationOperationStatus, std::io::Error> {
        let resource_uri = format!(
            "{}/registrations/{}/register?api-version=2021-11-01-preview",
            self.scope_id, registration_id
        );

        let client_cert_csr = self.generate_client_cert_csr(registration_id).await?;

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
                    client_cert_csr,
                }
            }
            _ => model::DeviceRegistration {
                registration_id: Some(registration_id.into()),
                tpm: None,
                client_cert_csr,
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
            "{}/registrations/{}/operations/{}?api-version=2021-11-01-preview",
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

        if matches!(auth_kind, DpsAuthKind::TpmDpsNonce { .. }) {
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

        let mut current_attempt = 1;
        let retry_limit = self.req_retries + 1;

        let res = loop {
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
                    http_common::MaybeProxyConnector::new(self.proxy_uri.clone(), None, &[])?
                }
                DpsAuthKind::SymmetricKey { sas_key: key } => {
                    let audience = format!("{}/registrations/{}", self.scope_id, registration_id);
                    let key_handle = self.key_client.load_key(key).await?;
                    let (connector, token) = get_sas_connector(
                        &audience,
                        key_handle,
                        &*self.key_client,
                        self.proxy_uri.clone(),
                        false,
                    )
                    .await?;
                    let authorization_header_value =
                        hyper::header::HeaderValue::from_str(&token)
                            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                    req.headers_mut()
                        .append(hyper::header::AUTHORIZATION, authorization_header_value);
                    connector
                }
                DpsAuthKind::TpmDpsNonce => {
                    let audience = format!("{}/registrations/{}", self.scope_id, registration_id);
                    let (connector, token) = get_sas_connector(
                        &audience,
                        (),
                        &*self.tpm_client,
                        self.proxy_uri.clone(),
                        true,
                    )
                    .await?;

                    let authorization_header_value =
                        hyper::header::HeaderValue::from_str(&token)
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
                        identity_cert,
                        identity_pk,
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

            let err = match tokio::time::timeout(self.req_timeout, client.request(req)).await {
                Ok(res) => match res {
                    Ok(res) => break res,
                    Err(err) => {
                        if err.is_connect() {
                            // Network error.
                            std::io::Error::new(std::io::ErrorKind::NotConnected, err)
                        } else {
                            std::io::Error::new(std::io::ErrorKind::Other, err)
                        }
                    }
                },
                Err(err) => err.into(),
            };

            log::warn!(
                "Provisioning failed to communicate with DPS (attempt {} of {}): {}",
                current_attempt,
                retry_limit,
                err
            );

            if current_attempt == retry_limit {
                return Err(err);
            }

            current_attempt += 1;
        };

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

                // TPM provisioning has special 2-step challenge/response flow, as detailed at
                // https://docs.microsoft.com/en-us/azure/iot-dps/concepts-tpm-attestation#detailed-attestation-process
                //
                // To keep the code DRY, a "psuedo" DpsAuthKind::TpmDpsNonce type is introduced
                // that is used as part of a recursive call to `request`, which will handle the
                // second-stage of the TPM provisioning flow after the auth key (provided by DPS)
                // has been imported into the TPM.

                self.tpm_client
                    .import_auth_key(
                        base64::decode(reg_result.authentication_key)
                            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?,
                    )
                    .await?;

                *auth_kind = DpsAuthKind::TpmDpsNonce;
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

    async fn generate_client_cert_csr(
        &self,
        registration_id: &str,
    ) -> Result<String, std::io::Error> {
        if let Ok(key_handle) = self.key_client.load_key_pair(&self.client_cert_key).await {
            if let Err(err) = self.key_client.delete_key_pair(&key_handle).await {
                log::warn!("Failed to delete client cert key: {}", err);
            }
        }

        let key_handle = self
            .key_client
            .create_key_pair_if_not_exists(&self.client_cert_key, Some("ec-p256:*"))
            .await?;
        let key_handle = std::ffi::CString::new(key_handle.0)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad key handle"))?;

        let (private_key, public_key) = {
            let mut key_engine = self.key_engine.lock().await;

            let private_key = key_engine.load_private_key(&key_handle).map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to load client cert private key: {}", err),
                )
            })?;
            let public_key = key_engine.load_public_key(&key_handle).map_err(|err| {
                std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to load client cert public key: {}", err),
                )
            })?;

            (private_key, public_key)
        };

        let mut csr = openssl::x509::X509Req::builder()?;
        csr.set_version(0)?;

        let mut name = openssl::x509::X509Name::builder()?;
        name.append_entry_by_text("CN", registration_id)?;
        let name = name.build();
        csr.set_subject_name(&name)?;

        csr.set_pubkey(&public_key)?;
        csr.sign(&private_key, openssl::hash::MessageDigest::sha256())?;

        let csr = csr.build().to_der()?;
        let csr = base64::encode(csr);

        Ok(csr)
    }
}
