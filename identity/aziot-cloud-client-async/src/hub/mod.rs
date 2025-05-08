// Copyright (c) Microsoft. All rights reserved.

use std::io::{Error, ErrorKind};

use aziot_identity_common::hub::{AuthMechanism, Module};

use http_common::{HttpRequest, HttpResponse};

const API_VERSION: &str = "api-version=2017-11-08-preview";

#[derive(Debug, serde::Deserialize)]
struct HubError {
    #[serde(rename = "Message", alias = "errorMessage")]
    pub message: String,

    // In nested mode, identity service will not be able to detect network errors between
    // the parent and IoT Hub. The parent edgeHub must detect network errors and propogate
    // them here.
    #[serde(rename = "networkError")]
    pub network_error: Option<bool>,
}

impl std::convert::From<HubError> for Error {
    fn from(err: HubError) -> Error {
        let error_kind = if err.network_error == Some(true) {
            ErrorKind::NotConnected
        } else {
            ErrorKind::Other
        };

        Error::new(error_kind, err.message)
    }
}

pub struct Client {
    device: aziot_identity_common::IoTHubDevice,

    key_client: crate::KeyClient,
    tpm_client: crate::TpmClient,

    timeout: std::time::Duration,
    retries: u32,

    proxy: Option<hyper::Uri>,
}

impl Client {
    #[must_use]
    pub fn new(
        device: &aziot_identity_common::IoTHubDevice,
        key_client: crate::KeyClient,
        tpm_client: crate::TpmClient,
    ) -> Self {
        Client {
            device: device.clone(),
            key_client,
            tpm_client,
            timeout: std::time::Duration::from_secs(30),
            retries: 0,
            proxy: None,
        }
    }

    #[must_use]
    pub fn with_retry(mut self, retries: u32) -> Self {
        self.retries = retries;

        self
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.timeout = timeout;

        self
    }

    #[must_use]
    pub fn with_proxy(mut self, proxy: Option<hyper::Uri>) -> Self {
        self.proxy = proxy;

        self
    }

    pub async fn create_module(
        &self,
        module_id: &str,
        authentication_type: Option<AuthMechanism>,
        managed_by: Option<String>,
    ) -> Result<Module, Error> {
        let body = Module {
            module_id: module_id.to_string(),
            managed_by,
            device_id: self.device.device_id.clone(),
            generation_id: None,
            authentication: authentication_type,
        };

        let request = self
            .build_request(hyper::Method::PUT, Some(module_id), Some(body))
            .await?;

        let response = request.json_response().await?;
        parse_hub_response(response)
    }

    pub async fn update_module(
        &self,
        module_id: &str,
        authentication_type: Option<AuthMechanism>,
        managed_by: Option<String>,
    ) -> Result<Module, Error> {
        let body = Module {
            module_id: module_id.to_string(),
            managed_by,
            device_id: self.device.device_id.clone(),
            generation_id: None,
            authentication: authentication_type,
        };

        let mut request = self
            .build_request(hyper::Method::PUT, Some(module_id), Some(body))
            .await?;
        request.add_header(hyper::header::IF_MATCH, "*")?;

        let response = request.json_response().await?;
        parse_hub_response(response)
    }

    pub async fn get_module(&self, module_id: &str) -> Result<Module, Error> {
        let request: HttpRequest<(), _> = self
            .build_request(hyper::Method::GET, Some(module_id), None)
            .await?;

        let response = request.json_response().await?;
        parse_hub_response(response)
    }

    pub async fn list_modules(&self) -> Result<Vec<Module>, Error> {
        let request: HttpRequest<(), _> =
            self.build_request(hyper::Method::GET, None, None).await?;
        let response = request.json_response().await?;

        parse_hub_response(response)
    }

    pub async fn delete_module(&self, module_id: &str) -> Result<(), Error> {
        let mut request: HttpRequest<(), _> = self
            .build_request(hyper::Method::DELETE, Some(module_id), None)
            .await?;
        request.add_header(hyper::header::IF_MATCH, "*")?;

        request.no_content_response().await
    }

    async fn build_request<TRequest>(
        &self,
        method: hyper::Method,
        module_id: Option<&str>,
        body: Option<TRequest>,
    ) -> Result<HttpRequest<TRequest, crate::CloudConnector>, Error>
    where
        TRequest: serde::Serialize,
    {
        let connector = crate::connector::from_auth(&self.device.credentials, self.proxy.clone())?;

        let uri = format!("https://{}", &self.device.local_gateway_hostname);
        let mut uri =
            url::Url::parse(&uri).map_err(|err| Error::new(ErrorKind::InvalidInput, err))?;

        let path = {
            let mut path = format!(
                "devices/{}/modules",
                percent_encoding::percent_encode(
                    self.device.device_id.as_bytes(),
                    crate::ENCODE_SET
                )
            );

            if let Some(module_id) = module_id {
                let module_id =
                    percent_encoding::percent_encode(module_id.as_bytes(), crate::ENCODE_SET);
                path = format!("{path}/{module_id}");
            }

            path
        };

        uri.set_path(&path);
        uri.set_query(Some(API_VERSION));

        let mut request = match method {
            hyper::Method::DELETE => HttpRequest::delete(connector, uri.as_str(), None),
            hyper::Method::GET => HttpRequest::get(connector, uri.as_str()),
            hyper::Method::PUT => {
                HttpRequest::put(connector, uri.as_str(), body.expect("missing PUT body"))
            }

            // No other methods are used with IoT Hub.
            _ => unreachable!(),
        }
        .with_retry(self.retries)
        .with_timeout(self.timeout);

        let auth_header = crate::connector::auth_header(
            crate::connector::Audience::Hub {
                hub_hostname: &self.device.iothub_hostname,
                device_id: &self.device.device_id,
            },
            &self.device.credentials,
            &self.key_client,
            &self.tpm_client,
        )
        .await?;

        if let Some(auth_header) = auth_header {
            request.add_header(hyper::header::AUTHORIZATION, &auth_header)?;
        }

        Ok(request)
    }
}

fn parse_hub_response<T>(response: HttpResponse) -> Result<T, Error>
where
    T: serde::de::DeserializeOwned,
{
    // 500 Internal Server Error is used by parent edgeHub modules to propagate network
    // Treat it as a network error by setting ErrorKind to NotConnected.
    if response.status() == hyper::StatusCode::INTERNAL_SERVER_ERROR {
        let hub_error =
            response.parse::<HubError, HubError>(&[hyper::StatusCode::INTERNAL_SERVER_ERROR])?;

        Err(Error::new(ErrorKind::NotConnected, hub_error.message))
    } else {
        response.parse_expect_ok::<T, HubError>()
    }
}
