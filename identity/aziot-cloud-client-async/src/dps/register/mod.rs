// Copyright (c) Microsoft. All rights reserved.

pub mod schema;

use std::io::{Error, ErrorKind};

use http_common::HttpRequest;
use serde_json::Value;

pub struct Register {
    endpoint: url::Url,
    auth: aziot_identity_common::Credentials,

    key_client: crate::KeyClient,
    key_engine: crate::KeyEngine,
    tpm_client: crate::TpmClient,

    timeout: std::time::Duration,
    retries: u32,

    proxy: Option<hyper::Uri>,

    client_cert_key: String,
}

impl Register {
    #[must_use]
    pub fn new(
        credentials: aziot_identity_common::Credentials,
        key_client: crate::KeyClient,
        key_engine: crate::KeyEngine,
        tpm_client: crate::TpmClient,
    ) -> Self {
        // The default DPS global endpoint.
        let endpoint = url::Url::parse("https://global.azure-devices-provisioning.net")
            .expect("hardcoded uri should parse");

        Register {
            endpoint,
            auth: credentials,
            key_client,
            key_engine,
            tpm_client,
            timeout: std::time::Duration::from_secs(30),
            retries: 0,
            proxy: None,
            client_cert_key: aziot_identity_common::DPS_IDENTITY_CERT_KEY.to_string(),
        }
    }

    pub fn with_endpoint(mut self, endpoint: url::Url) -> Self {
        self.endpoint = endpoint;

        self
    }

    pub fn with_retry(mut self, retries: u32) -> Self {
        self.retries = retries;

        self
    }

    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;

        self
    }

    pub fn with_proxy(mut self, proxy: Option<hyper::Uri>) -> Self {
        self.proxy = proxy;

        self
    }

    pub fn with_client_cert_key(mut self, client_cert_key: String) -> Self {
        self.client_cert_key = client_cert_key;

        self
    }

    pub async fn register(
        self,
        scope_id: &str,
        registration_id: &str,
        payload: Option<Value>,
    ) -> Result<schema::Device, Error> {
        let connector = crate::connector::from_auth(&self.auth, self.proxy.clone())?;

        let register_uri = {
            let register_path = format!("{}/registrations/{}/register", scope_id, registration_id);

            let mut register_uri = self.endpoint.clone();
            register_uri.set_path(&register_path);
            register_uri.set_query(Some(super::API_VERSION));

            register_uri
        };

        // Perform the DPS registration.
        let client_cert_csr = self.generate_client_cert_csr(registration_id).await?;

        let register_body = schema::request::DeviceRegistration {
            registration_id: registration_id.to_string(),
            client_cert_csr: Some(client_cert_csr),
            payload: payload.clone(),
        };

        let response = self
            .register_once(
                connector.clone(),
                scope_id,
                registration_id,
                register_uri.as_str(),
                register_body,
            )
            .await;

        // Check the response. Some responses indicate the registration should be retried with a
        // different body.
        let device = match response {
            Ok(device) => device,
            Err(err) => match err.kind() {
                ErrorKind::InvalidInput => {
                    log::info!(
                        "DPS is not configured to accept identity cert CSR. Provisioning without CSR."
                    );

                    if let Ok(key_handle) =
                        self.key_client.load_key_pair(&self.client_cert_key).await
                    {
                        if let Err(err) = self.key_client.delete_key_pair(&key_handle).await {
                            log::warn!("Failed to delete client cert key: {}", err);
                        }
                    }

                    let register_body = schema::request::DeviceRegistration {
                        registration_id: registration_id.to_string(),
                        client_cert_csr: None,
                        payload,
                    };

                    self.register_once(
                        connector,
                        scope_id,
                        registration_id,
                        register_uri.as_str(),
                        register_body,
                    )
                    .await?
                }

                _ => return Err(err),
            },
        };

        log::info!("DPS registration complete.");

        Ok(device)
    }

    async fn get_tpm_nonce(
        &self,
        connector: crate::CloudConnector,
        uri: &str,
        registration_id: &str,
        payload: Option<Value>,
    ) -> Result<(), Error> {
        let request_body = {
            let tpm_keys = self.tpm_client.get_tpm_keys().await?;

            schema::request::TpmRegistration {
                registration_id: registration_id.to_string(),
                tpm: tpm_keys.into(),
                payload,
            }
        };

        let response = HttpRequest::put(connector, uri, request_body)
            .with_retry(self.retries)
            .with_timeout(self.timeout)
            .json_response()
            .await?;

        // DPS should respond with 401 Unauthorized and present the encrypted nonce.
        let response = response.parse::<schema::response::TpmAuthKey, super::ServiceError>(&[
            hyper::StatusCode::UNAUTHORIZED,
        ])?;

        let auth_key = base64::decode(response.authentication_key)
            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

        // Decrypt and import the nonce into the TPM. This nonce will be used to sign a SAS token
        // for the second part of provisioning.
        self.tpm_client.import_auth_key(auth_key).await?;

        Ok(())
    }

    /// Performs a single round of DPS registration.
    ///
    /// Some DPS configurations may require multiple rounds, so this function may be called
    /// multiple times for a single DPS registration request.
    async fn register_once(
        &self,
        connector: crate::CloudConnector,
        scope_id: &str,
        registration_id: &str,
        register_uri: &str,
        register_body: schema::request::DeviceRegistration,
    ) -> Result<schema::Device, Error> {
        // Registration with TPM has an additional step to get an encrypted nonce
        // from DPS. After decrypting and importing the nonce, the remaining registration
        // steps are the same as registration with SAS key.
        if let aziot_identity_common::Credentials::Tpm = &self.auth {
            self.get_tpm_nonce(
                connector.clone(),
                register_uri,
                registration_id,
                register_body.payload.clone(),
            )
            .await?;
        }

        // Determine the Authorization header to include.
        let auth_header = crate::connector::auth_header(
            crate::connector::Audience::Registration {
                scope_id,
                registration_id,
            },
            &self.auth,
            &self.key_client,
            &self.tpm_client,
        )
        .await?;

        // Send the DPS registration request.
        let mut register_request = HttpRequest::put(connector.clone(), register_uri, register_body)
            .with_retry(self.retries)
            .with_timeout(self.timeout);

        if let Some(auth_header) = &auth_header {
            register_request.add_header(hyper::header::AUTHORIZATION, auth_header)?;
        }

        log::info!("Sending DPS registration request.");
        let response = register_request.json_response().await?;

        // Determine the registration request's operation ID.
        let operation_id = {
            let response = response.parse::<super::OperationStatus, super::ServiceError>(&[
                hyper::StatusCode::OK,
                hyper::StatusCode::ACCEPTED,
            ])?;

            response.operation_id
        };

        // Determine the registration request's status URI.
        let status_uri = {
            let status_path = format!(
                "{}/registrations/{}/operations/{}",
                scope_id, registration_id, operation_id
            );

            let mut status_uri = self.endpoint.clone();
            status_uri.set_path(&status_path);
            status_uri.set_query(Some(super::API_VERSION));

            status_uri
        };

        // Query the status URI until the registration finishes.
        tokio::time::sleep(super::POLL_PERIOD).await;

        loop {
            // Since this request is already in a retry loop, with_retry() is not used
            // with this request.
            let mut status_request: HttpRequest<(), _> =
                HttpRequest::get(connector.clone(), status_uri.as_str());

            if let Some(auth_header) = &auth_header {
                status_request.add_header(hyper::header::AUTHORIZATION, auth_header)?;
            }

            log::info!("Checking DPS registration status.");
            let response = status_request.json_response().await?;

            let registration = response
                .parse::<schema::response::DeviceRegistration, super::ServiceError>(&[
                    hyper::StatusCode::OK,
                    hyper::StatusCode::ACCEPTED,
                ])?;

            match registration {
                schema::response::DeviceRegistration::Assigned { device, tpm } => {
                    if let Some(tpm) = tpm {
                        let auth_key = base64::decode(tpm.authentication_key)
                            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

                        self.tpm_client.import_auth_key(auth_key).await?;
                        log::info!("Imported DPS authentication key into TPM.");
                    }

                    return Ok(device);
                }

                schema::response::DeviceRegistration::Assigning { .. } => {
                    log::info!("DPS registration is still in progress.");

                    tokio::time::sleep(super::POLL_PERIOD).await;
                }

                schema::response::DeviceRegistration::Failed(error) => {
                    // Some failures mean the registration should be retried with a different request
                    // body. Return the error and let the caller of this function determine if retry
                    // is necessary.
                    return Err(error.into());
                }
            }
        }
    }

    async fn generate_client_cert_csr(&self, registration_id: &str) -> Result<String, Error> {
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
            .map_err(|_| Error::new(ErrorKind::InvalidData, "bad key handle"))?;

        let (private_key, public_key) = {
            let mut key_engine = self.key_engine.lock().await;

            let private_key = key_engine.load_private_key(&key_handle).map_err(|err| {
                Error::new(
                    ErrorKind::Other,
                    format!("Failed to load client cert private key: {}", err),
                )
            })?;
            let public_key = key_engine.load_public_key(&key_handle).map_err(|err| {
                Error::new(
                    ErrorKind::Other,
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
