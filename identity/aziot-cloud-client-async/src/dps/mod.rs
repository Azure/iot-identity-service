// Copyright (c) Microsoft. All rights reserved.

pub mod schema;

use std::io::{Error, ErrorKind};

use crate::request::HttpRequest;

const API_VERSION: &str = "api-version=2021-06-01";

pub struct Client {
    endpoint: url::Url,
    auth: aziot_identity_common::Credentials,

    key_client: crate::KeyClient,
    key_engine: crate::KeyEngine,
    cert_client: crate::CertClient,
    tpm_client: crate::TpmClient,

    timeout: std::time::Duration,
    retries: u32,

    proxy: Option<hyper::Uri>,
}

impl Client {
    pub fn new(
        credentials: aziot_identity_common::Credentials,
        key_client: crate::KeyClient,
        key_engine: crate::KeyEngine,
        cert_client: crate::CertClient,
        tpm_client: crate::TpmClient,
    ) -> Self {
        // The default DPS global endpoint.
        let endpoint = url::Url::parse("https://global.azure-devices-provisioning.net")
            .expect("hardcoded uri should parse");

        Client {
            endpoint,
            auth: credentials,
            key_client,
            key_engine,
            cert_client,
            tpm_client,
            timeout: std::time::Duration::from_secs(30),
            retries: 0,
            proxy: None,
        }
    }

    pub fn with_endpoint(mut self, endpoint: url::Url) -> Self {
        self.endpoint = endpoint;

        self
    }

    pub fn with_retry(mut self, timeout: std::time::Duration, retries: u32) -> Self {
        self.timeout = timeout;
        self.retries = retries;

        self
    }

    pub fn with_proxy(mut self, proxy: Option<hyper::Uri>) -> Self {
        self.proxy = proxy;

        self
    }

    pub async fn register(
        &self,
        scope_id: &str,
        registration_id: &str,
    ) -> Result<schema::Device, Error> {
        let connector = crate::connector::from_auth(
            &self.auth,
            self.proxy.clone(),
            &self.key_client,
            &self.key_engine,
            &self.cert_client,
        )
        .await?;

        let register_uri = {
            let register_path = format!("{}/registrations/{}/register", scope_id, registration_id);

            let mut register_uri = self.endpoint.clone();
            register_uri.set_path(&register_path);
            register_uri.set_query(Some(API_VERSION));

            register_uri
        };

        // Perform the DPS registration.
        let register_body = schema::request::DeviceRegistration {
            registration_id: registration_id.to_string(),
        };

        let device = self
            .register_once(
                connector,
                scope_id,
                registration_id,
                register_uri.as_str(),
                register_body,
            )
            .await?
            .map_err(|err| Error::new(ErrorKind::Other, err.message))?;

        log::info!("DPS registration complete.");

        Ok(device)
    }

    async fn get_tpm_nonce(
        &self,
        connector: crate::CloudConnector,
        uri: &str,
        registration_id: &str,
    ) -> Result<(), Error> {
        let request_body = {
            let tpm_keys = self.tpm_client.get_tpm_keys().await?;

            schema::request::TpmRegistration {
                registration_id: registration_id.to_string(),
                tpm: Some(tpm_keys.into()),
            }
        };

        let (response_status, response_body) = HttpRequest::put(connector, uri, request_body)
            .with_retry(self.timeout, self.retries)
            .json_response()
            .await?;

        // DPS should respond with 401 Unauthorized and present the encrypted nonce.
        if response_status != hyper::StatusCode::UNAUTHORIZED {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid HTTP status code for TPM registration",
            ));
        }

        let auth_key = {
            let auth_key: schema::response::TpmAuthKey = serde_json::from_slice(&response_body)
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

            base64::decode(auth_key.authentication_key)
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?
        };

        // Decrypt and import the nonce into the TPM. This nonce will be used to sign a SAS token
        // for the second part of provisioning.
        self.tpm_client.import_auth_key(auth_key).await?;

        Ok(())
    }

    /// Performs a single round of DPS registration.
    ///
    /// Some DPS configurations may require multiple rounds. Note that this function returns a
    /// nested `Result`.
    /// - The first layer error (`std::io::Error`) is returned if DPS could not be reached or
    /// another unrecoverable error occurred.
    /// - The second layer error (`schema::response::ServiceError`) is returned if the DPS
    /// service rejected the registration. The caller of this function will determine whether
    /// to perform another round of DPS registration based on this error.
    async fn register_once(
        &self,
        connector: crate::CloudConnector,
        scope_id: &str,
        registration_id: &str,
        register_uri: &str,
        register_body: schema::request::DeviceRegistration,
    ) -> Result<Result<schema::Device, schema::response::ServiceError>, Error> {
        // Registration with TPM has an additional step to get an encrypted nonce
        // from DPS. After decrypting and importing the nonce, the remaining registration
        // steps are the same as registration with SAS key.
        if let aziot_identity_common::Credentials::Tpm = &self.auth {
            self.get_tpm_nonce(connector.clone(), register_uri, registration_id)
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
            .with_retry(self.timeout, self.retries);

        if let Some(auth_header) = &auth_header {
            register_request.add_header(hyper::header::AUTHORIZATION, auth_header)?;
        }

        log::info!("Sending DPS registration request.");
        let (response_status, response_body) = register_request.json_response().await?;

        // Determine the registration request's operation ID.
        let operation_id = if response_status.is_success() {
            let response_body: schema::response::OperationStatus =
                serde_json::from_slice(&response_body)
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

            response_body.operation_id
        } else if response_status.is_client_error() || response_status.is_server_error() {
            let response_body: schema::response::ServiceError =
                serde_json::from_slice(&response_body)
                    .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

            return Err(Error::new(ErrorKind::Other, response_body.message));
        } else {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "invalid HTTP status code",
            ));
        };

        // Determine the registration request's status URI.
        let status_uri = {
            let status_path = format!(
                "{}/registrations/{}/operations/{}",
                scope_id, registration_id, operation_id
            );

            let mut status_uri = self.endpoint.clone();
            status_uri.set_path(&status_path);
            status_uri.set_query(Some(API_VERSION));

            status_uri
        };

        // Query the status URI until the registration finishes.
        const POLL_PERIOD: tokio::time::Duration = tokio::time::Duration::from_secs(5);
        tokio::time::sleep(POLL_PERIOD).await;

        loop {
            // Since this request is already in a retry loop, with_retry() is not used
            // with this request.
            let mut status_request: HttpRequest<()> =
                HttpRequest::get(connector.clone(), status_uri.as_str());

            if let Some(auth_header) = &auth_header {
                status_request.add_header(hyper::header::AUTHORIZATION, auth_header)?;
            }

            log::info!("Checking DPS registration status.");
            let (response_status, response_body) = status_request.json_response().await?;

            let registration = if response_status.is_success() {
                let response_body: schema::response::DeviceRegistration =
                    serde_json::from_slice(&response_body)
                        .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

                response_body
            } else if response_status.is_client_error() || response_status.is_server_error() {
                let response_body: schema::response::ServiceError =
                    serde_json::from_slice(&response_body)
                        .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

                return Ok(Err(response_body));
            } else {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "invalid HTTP status code",
                ));
            };

            match registration {
                schema::response::DeviceRegistration::Assigned { device, tpm } => {
                    if let Some(tpm) = tpm {
                        let auth_key = base64::decode(tpm.authentication_key)
                            .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

                        self.tpm_client.import_auth_key(auth_key).await?;
                        log::info!("Imported DPS authentication key into TPM.");
                    }

                    return Ok(Ok(device));
                }

                schema::response::DeviceRegistration::Assigning { .. } => {
                    log::info!("DPS registration is still in progress.");

                    tokio::time::sleep(POLL_PERIOD).await;
                }

                schema::response::DeviceRegistration::Failed(error) => {
                    // Some failures mean the registration should be retried with a different request
                    // body. Return the error and let the caller of this function determine if retry
                    // is necessary.
                    return Ok(Err(error));
                }
            }
        }
    }
}
