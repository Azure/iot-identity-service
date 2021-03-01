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
    pub async fn get_token(&self) -> Result<String, std::io::Error> {
        let access_token_provider_uri = "mtlsauth.windows-ppe.net";
        let tenant_id = "c92dd71d-c78b-49e0-8c86-1f6b5301a825";
        let azure_resource_scope = "https://ppe.cognitiveservices.azure.com/.default";
        let app_id = "7b69073c-ca57-403d-b649-dc1ee28bdb16";
        let device_id = "";

        let uri = format!(
            "https://{}/{}/oauth2/v2.0/token?debugmodeflight=true",
            access_token_provider_uri, tenant_id
        );

        let body = AAD_Request {
            grant_type: "sub_mlts",
            scope: azure_resource_scope,
            client_id: app_id,
            external_device_id: device_id,
        };

        println!("\n\n\nGetting token.\nUri: {}\nBody:{:#?}", uri, body);

        let res: AAD_Response = self
            .request(http::Method::POST, &uri, Some(&body), false)
            .await?;

        Ok(res.access_token)
    }

    async fn request<TRequest, TResponse>(
        &self,
        method: http::Method,
        uri: &str,
        body: Option<&TRequest>,
        add_if_match: bool,
    ) -> std::io::Result<TResponse>
    where
        TRequest: serde::Serialize,
        TResponse: serde::de::DeserializeOwned,
    {
        let uri = format!("https://{}{}", "ppe", uri);

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

        let connector = match self.device.credentials.clone() {
            aziot_identity_common::Credentials::SharedPrivateKey(key) => {
                return Err(std::io::Error::from(std::io::ErrorKind::Other)); //TODO: Do Error stuff
            }
            aziot_identity_common::Credentials::Tpm => {
                return Err(std::io::Error::from(std::io::ErrorKind::Other)); //TODO: Do Error stuff
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
                    self.proxy_uri.clone(),
                )
                .await?
            }
        };

        let client: hyper::Client<_, hyper::Body> = hyper::Client::builder().build(connector);
        log::debug!("AAD request {:?}", req);

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
        log::debug!("AAD response status {:?}", res_status_code);
        log::debug!("AAD response headers{:?}", headers);

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
        log::debug!("AAD response body {:?}", body);

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
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Error {
    #[serde(alias = "Message")]
    pub message: std::borrow::Cow<'static, str>,
}

#[derive(Debug, serde::Serialize)]
pub struct AAD_Request<'a> {
    pub grant_type: &'a str,
    pub scope: &'a str,
    pub client_id: &'a str,
    pub external_device_id: &'a str,
}


#[derive(Debug, serde::Deserialize)]
pub struct AAD_Response {
    pub access_token: String,
}
