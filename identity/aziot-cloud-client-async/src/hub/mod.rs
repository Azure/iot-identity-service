// Copyright (c) Microsoft. All rights reserved.

use std::io::{Error, ErrorKind};

use aziot_identity_common::hub::{AuthMechanism, Module};

use crate::request::HttpRequest;

const API_VERSION: &str = "api-version=2020-05-31-preview";

pub struct Client {
    device: aziot_identity_common::IoTHubDevice,

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
        device: &aziot_identity_common::IoTHubDevice,
        key_client: crate::KeyClient,
        key_engine: crate::KeyEngine,
        cert_client: crate::CertClient,
        tpm_client: crate::TpmClient,
    ) -> Self {
        Client {
            device: device.clone(),
            key_client,
            key_engine,
            cert_client,
            tpm_client,
            timeout: std::time::Duration::from_secs(30),
            retries: 0,
            proxy: None,
        }
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

    pub async fn create_module(
        &self,
        _module_id: &str,
        _authentication_type: Option<AuthMechanism>,
        _managed_by: Option<String>,
    ) -> Result<Module, Error> {
        todo!()
    }

    pub async fn update_module(
        &self,
        module_id: &str,
        _authentication_type: Option<AuthMechanism>,
        _managed_by: Option<String>,
    ) -> Result<Module, Error> {
        let mut request: HttpRequest<()> = self
            .build_request(hyper::Method::PUT, Some(module_id))
            .await?;
        request.add_header(hyper::header::IF_MATCH, "*")?;

        todo!()
    }

    pub async fn get_module(&self, _module_id: &str) -> Result<Module, Error> {
        todo!()
    }

    pub async fn list_modules(&self) -> Result<Vec<Module>, Error> {
        let request: HttpRequest<()> = self.build_request(hyper::Method::GET, None).await?;
        let response = request.json_response().await?;

        parse_response(response)
    }

    pub async fn delete_module(&self, module_id: &str) -> Result<(), Error> {
        let mut request: HttpRequest<()> = self
            .build_request(hyper::Method::DELETE, Some(module_id))
            .await?;
        request.add_header(hyper::header::IF_MATCH, "*")?;

        todo!()
    }

    async fn build_request<TRequest>(
        &self,
        method: hyper::Method,
        module_id: Option<&str>,
    ) -> Result<HttpRequest<TRequest>, Error>
    where
        TRequest: serde::Serialize,
    {
        let connector = crate::connector::from_auth(
            &self.device.credentials,
            self.proxy.clone(),
            &self.key_client,
            &self.key_engine,
            &self.cert_client,
        )
        .await?;

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
                path = format!("{}/{}", path, module_id);
            }

            path
        };

        uri.set_path(&path);
        uri.set_query(Some(API_VERSION));

        let mut request = match method {
            hyper::Method::GET => HttpRequest::get(connector, uri.as_str()),

            // No other methods are used with IoT Hub.
            _ => unreachable!(),
        }
        .with_retry(self.timeout, self.retries);

        let audience = format!(
            "{}/devices/{}",
            self.device.iothub_hostname, self.device.device_id
        );
        let auth_header = crate::connector::auth_header(
            &audience,
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

#[derive(Debug, serde::Deserialize)]
struct HubError {
    #[serde(rename = "Message")]
    pub message: String,
}

fn parse_response<TResponse>(
    response: (hyper::StatusCode, hyper::body::Bytes),
) -> Result<TResponse, Error>
where
    TResponse: serde::de::DeserializeOwned,
{
    let (status, body) = response;

    if status == hyper::StatusCode::OK || status == hyper::StatusCode::CREATED {
        let response =
            serde_json::from_slice(&body).map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

        Ok(response)
    } else if status.is_client_error() || status.is_server_error() {
        let error: HubError =
            serde_json::from_slice(&body).map_err(|err| Error::new(ErrorKind::InvalidData, err))?;

        Err(Error::new(ErrorKind::Other, error.message))
    } else {
        Err(Error::new(
            ErrorKind::InvalidData,
            "invalid HTTP status code",
        ))
    }
}
