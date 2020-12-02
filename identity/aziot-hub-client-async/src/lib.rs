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

use aziot_cloud_client_async_common::{get_sas_connector, get_x509_connector, MaybeProxyClient};

pub const IOT_HUB_ENCODE_SET: &percent_encoding::AsciiSet =
    &http_common::PATH_SEGMENT_ENCODE_SET.add(b'=');

pub struct Client {
    device: aziot_identity_common::IoTHubDevice,
    key_client: Arc<aziot_key_client_async::Client>,
    key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
    cert_client: Arc<aziot_cert_client_async::Client>,
    tpm_client: Arc<aziot_tpm_client_async::Client>,
    proxy_uri: Option<hyper::Uri>,
}

impl Client {
    #[must_use]
    pub fn new(
        device: aziot_identity_common::IoTHubDevice,
        key_client: Arc<aziot_key_client_async::Client>,
        key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
        cert_client: Arc<aziot_cert_client_async::Client>,
        tpm_client: Arc<aziot_tpm_client_async::Client>,
        proxy_uri: Option<hyper::Uri>,
    ) -> Self {
        Client {
            device,
            key_client,
            key_engine,
            cert_client,
            tpm_client,
            proxy_uri,
        }
    }
}

impl Client {
    pub async fn create_module(
        &self,
        module_id: &str,
        authentication_type: Option<aziot_identity_common::hub::AuthMechanism>,
        managed_by: Option<String>,
    ) -> Result<aziot_identity_common::hub::Module, std::io::Error> {
        let uri = format!(
            "/devices/{}/modules/{}?api-version=2017-11-08-preview",
            percent_encoding::percent_encode(&self.device.device_id.as_bytes(), IOT_HUB_ENCODE_SET),
            percent_encoding::percent_encode(module_id.as_bytes(), IOT_HUB_ENCODE_SET),
        );

        let body = aziot_identity_common::hub::Module {
            module_id: module_id.into(),
            managed_by,
            device_id: self.device.device_id.clone(),
            generation_id: None,
            authentication: authentication_type,
        };

        let res: aziot_identity_common::hub::Module = self
            .request(&self.device, http::Method::PUT, &uri, Some(&body), false)
            .await?;

        Ok(res)
    }

    pub async fn update_module(
        &self,
        module_id: &str,
        authentication_type: Option<aziot_identity_common::hub::AuthMechanism>,
        managed_by: Option<String>,
    ) -> Result<aziot_identity_common::hub::Module, std::io::Error> {
        let uri = format!(
            "/devices/{}/modules/{}?api-version=2017-11-08-preview",
            percent_encoding::percent_encode(&self.device.device_id.as_bytes(), IOT_HUB_ENCODE_SET),
            percent_encoding::percent_encode(module_id.as_bytes(), IOT_HUB_ENCODE_SET),
        );

        let body = aziot_identity_common::hub::Module {
            module_id: module_id.into(),
            managed_by,
            device_id: self.device.device_id.clone(),
            generation_id: None,
            authentication: authentication_type,
        };

        let res: aziot_identity_common::hub::Module = self
            .request(&self.device, http::Method::PUT, &uri, Some(&body), true)
            .await?;
        Ok(res)
    }

    pub async fn get_module(
        &self,
        module_id: &str,
    ) -> Result<aziot_identity_common::hub::Module, std::io::Error> {
        let uri = format!(
            "/devices/{}/modules/{}?api-version=2017-11-08-preview",
            percent_encoding::percent_encode(&self.device.device_id.as_bytes(), IOT_HUB_ENCODE_SET),
            percent_encoding::percent_encode(module_id.as_bytes(), IOT_HUB_ENCODE_SET),
        );

        let res: aziot_identity_common::hub::Module = self
            .request::<(), _>(&self.device, http::Method::GET, &uri, None, false)
            .await?;
        Ok(res)
    }

    pub async fn get_modules(
        &self,
    ) -> Result<Vec<aziot_identity_common::hub::Module>, std::io::Error> {
        let uri = format!(
            "/devices/{}/modules?api-version=2017-11-08-preview",
            percent_encoding::percent_encode(&self.device.device_id.as_bytes(), IOT_HUB_ENCODE_SET),
        );

        let res: Vec<aziot_identity_common::hub::Module> = self
            .request::<(), _>(&self.device, http::Method::GET, &uri, None, false)
            .await?;
        Ok(res)
    }

    pub async fn delete_module(&self, module_id: &str) -> Result<(), std::io::Error> {
        let uri = format!(
            "/devices/{}/modules/{}?api-version=2017-11-08-preview",
            percent_encoding::percent_encode(&self.device.device_id.as_bytes(), IOT_HUB_ENCODE_SET),
            percent_encoding::percent_encode(module_id.as_bytes(), IOT_HUB_ENCODE_SET),
        );

        let () = self
            .request_no_content::<()>(&self.device, http::Method::DELETE, &uri, None)
            .await?;
        Ok(())
    }

    async fn request<TRequest, TResponse>(
        &self,
        hub_device: &aziot_identity_common::IoTHubDevice,
        method: http::Method,
        uri: &str,
        body: Option<&TRequest>,
        add_if_match: bool,
    ) -> std::io::Result<TResponse>
    where
        TRequest: serde::Serialize,
        TResponse: serde::de::DeserializeOwned,
    {
        let uri = format!("https://{}{}", hub_device.iothub_hostname, uri);

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

        if add_if_match {
            req.headers_mut().insert(
                hyper::header::IF_MATCH,
                hyper::header::HeaderValue::from_static("*"),
            );
        }

        let connector = match hub_device.credentials.clone() {
            aziot_identity_common::Credentials::SharedPrivateKey(key) => {
                let audience = format!(
                    "{}/devices/{}",
                    hub_device.iothub_hostname, hub_device.device_id
                );
                let (connector, token) =
                    get_sas_connector(&audience, &key, &*self.key_client, false).await?;

                let authorization_header_value = hyper::header::HeaderValue::from_str(&token)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                req.headers_mut()
                    .append(hyper::header::AUTHORIZATION, authorization_header_value);
                connector
            }
            aziot_identity_common::Credentials::Tpm => {
                let audience = format!(
                    "{}/devices/{}",
                    hub_device.iothub_hostname, hub_device.device_id
                );
                let (connector, token) =
                    get_sas_connector(&audience, "", &*self.tpm_client, false).await?;

                let authorization_header_value = hyper::header::HeaderValue::from_str(&token)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                req.headers_mut()
                    .append(hyper::header::AUTHORIZATION, authorization_header_value);
                connector
            }
            aziot_identity_common::Credentials::X509 {
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

        let client = MaybeProxyClient::build(self.proxy_uri.clone(), connector)?;

        log::debug!("IoTHub request {:?}", req);

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
        log::debug!("IoTHub response status {:?}", res_status_code);
        log::debug!("IoTHub response headers{:?}", headers);

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
        log::debug!("IoTHub response body {:?}", body);

        let res: TResponse = match res_status_code {
            hyper::StatusCode::OK | hyper::StatusCode::CREATED => {
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
                let res: crate::Error = serde_json::from_slice(&body)
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

    async fn request_no_content<TRequest>(
        &self,
        hub_device: &aziot_identity_common::IoTHubDevice,
        method: http::Method,
        uri: &str,
        body: Option<&TRequest>,
    ) -> std::io::Result<()>
    where
        TRequest: serde::Serialize,
    {
        let uri = format!("https://{}{}", hub_device.iothub_hostname, uri);

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
            req.body(Default::default())
        };
        let mut req = req.expect("cannot fail to create hyper request");

        req.headers_mut().insert(
            hyper::header::IF_MATCH,
            hyper::header::HeaderValue::from_static("*"),
        );

        let connector = match hub_device.credentials.clone() {
            aziot_identity_common::Credentials::SharedPrivateKey(key) => {
                let audience = format!(
                    "{}/devices/{}",
                    hub_device.iothub_hostname, hub_device.device_id
                );
                let (connector, token) =
                    get_sas_connector(&audience, &key, &*self.key_client, false).await?;

                let authorization_header_value = hyper::header::HeaderValue::from_str(&token)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                req.headers_mut()
                    .append(hyper::header::AUTHORIZATION, authorization_header_value);
                connector
            }
            aziot_identity_common::Credentials::Tpm => {
                let audience = format!(
                    "{}/devices/{}",
                    hub_device.iothub_hostname, hub_device.device_id
                );
                let (connector, token) =
                    get_sas_connector(&audience, "", &*self.tpm_client, false).await?;

                let authorization_header_value = hyper::header::HeaderValue::from_str(&token)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                req.headers_mut()
                    .append(hyper::header::AUTHORIZATION, authorization_header_value);
                connector
            }
            aziot_identity_common::Credentials::X509 {
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

        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().build(connector);

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

        let body = hyper::body::to_bytes(body)
            .await
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        match res_status_code {
            hyper::StatusCode::NO_CONTENT => Ok(()),

            res_status_code
                if res_status_code.is_client_error() || res_status_code.is_server_error() =>
            {
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

                if !is_json {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "malformed HTTP response",
                    ));
                }

                let res: crate::Error = serde_json::from_slice(&body)
                    .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
                Err(std::io::Error::new(std::io::ErrorKind::Other, res.message))
            }

            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "malformed HTTP response",
            )),
        }
    }
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Error {
    #[serde(alias = "Message")]
    pub message: std::borrow::Cow<'static, str>,
}
