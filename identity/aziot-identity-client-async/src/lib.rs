// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(clippy::must_use_candidate, clippy::missing_errors_doc)]

use std::time::Duration;

use aziot_identity_common::{Identity, ID_TYPE_AZIOT, ID_TYPE_LOCAL};

// All exports of aziot_identity_common_http are used in this file.
#[allow(clippy::wildcard_imports)]
use aziot_identity_common_http::*;

use http_common::{ErrorBody, HttpRequest};

macro_rules! make_uri {
    ($path:literal, $api_version:expr) => {
        &format!(
            "http://identityd.sock{}?api-version={}",
            $path, $api_version
        )
    };
    ($path:literal, $api_version:expr, $type:expr) => {
        &format!(
            "http://identityd.sock{}?api-version={}&type={}",
            $path, $api_version, $type
        )
    };
    ($path:literal, $api_version:expr, $type:expr, $name:ident) => {
        &format!(
            "http://identityd.sock{}/{}?api-version={}&type={}",
            $path,
            percent_encoding::percent_encode(
                $name.as_bytes(),
                http_common::PATH_SEGMENT_ENCODE_SET
            ),
            $api_version,
            $type
        )
    };
}

#[derive(Debug)]
pub struct Client {
    api_version: ApiVersion,
    connector: http_common::Connector,
    max_retries: u32,
    timeout: Duration,
}

impl Client {
    pub fn new(
        api_version: ApiVersion,
        connector: http_common::Connector,
        max_retries: u32,
    ) -> Self {
        // use timeout of 10 minutes to allow identityd to backoff throttled calls
        let timeout = Duration::from_secs(10 * 60);

        Client {
            api_version,
            connector,
            max_retries,
            timeout,
        }
    }

    pub async fn get_caller_identity(&self) -> Result<Identity, std::io::Error> {
        let uri = make_uri!("/identities/identity", self.api_version);

        let request: HttpRequest<(), _> = HttpRequest::get(self.connector.clone(), uri)
            .with_retry(self.max_retries)
            .with_timeout(self.timeout);

        let response = request.json_response().await?;
        let response: get_caller_identity::Response =
            response.parse_expect_ok::<_, ErrorBody<'_>>()?;

        Ok(response.identity)
    }

    pub async fn get_device_identity(&self) -> Result<Identity, std::io::Error> {
        let uri = make_uri!("/identities/device", self.api_version);

        let body = get_device_identity::Request {
            id_type: ID_TYPE_AZIOT.to_string(),
        };

        let request = HttpRequest::post(self.connector.clone(), uri, Some(body))
            .with_retry(self.max_retries)
            .with_timeout(self.timeout);

        let response = request.json_response().await?;
        let response: get_device_identity::Response =
            response.parse_expect_ok::<_, ErrorBody<'_>>()?;

        Ok(response.identity)
    }

    pub async fn reprovision(&self) -> Result<(), std::io::Error> {
        let uri = make_uri!("/identities/device/reprovision", self.api_version);

        let body = reprovision_device::Request {
            id_type: ID_TYPE_AZIOT.to_string(),
        };

        let request = HttpRequest::post(self.connector.clone(), uri, Some(body))
            .with_retry(self.max_retries)
            .with_timeout(self.timeout);

        request.no_content_response().await
    }

    pub async fn get_provisioning_info(
        &self,
    ) -> Result<get_provisioning_info::Response, std::io::Error> {
        let uri = make_uri!("/identities/provisioning", self.api_version);

        let request: HttpRequest<(), _> = HttpRequest::get(self.connector.clone(), uri)
            .with_retry(self.max_retries)
            .with_timeout(self.timeout);

        let response = request.json_response().await?;
        let response: get_provisioning_info::Response =
            response.parse_expect_ok::<_, ErrorBody<'_>>()?;

        Ok(response)
    }

    pub async fn create_module_identity(
        &self,
        module_name: &str,
    ) -> Result<Identity, std::io::Error> {
        let uri = make_uri!("/identities/modules", self.api_version);

        let body = create_module_identity::Request {
            id_type: ID_TYPE_AZIOT.to_string(),
            module_id: module_name.to_string(),
            opts: None,
        };

        let request = HttpRequest::post(self.connector.clone(), uri, Some(body))
            .with_retry(self.max_retries)
            .with_timeout(self.timeout);

        let response = request.json_response().await?;
        let response: create_module_identity::Response =
            response.parse_expect_ok::<_, ErrorBody<'_>>()?;

        Ok(response.identity)
    }

    pub async fn create_local_identity(
        &self,
        module_name: &str,
        opts: Option<aziot_identity_common::LocalIdOpts>,
    ) -> Result<Identity, std::io::Error> {
        let uri = make_uri!("/identities/modules", self.api_version);

        #[allow(clippy::redundant_closure)] // closure needed for map()
        let body = create_module_identity::Request {
            id_type: ID_TYPE_LOCAL.to_string(),
            module_id: module_name.to_string(),
            opts: opts.map(|opts| create_module_identity::CreateModuleOpts::LocalIdOpts(opts)),
        };

        let request = HttpRequest::post(self.connector.clone(), uri, Some(body))
            .with_retry(self.max_retries)
            .with_timeout(self.timeout);

        let response = request.json_response().await?;
        let response: create_module_identity::Response =
            response.parse_expect_ok::<_, ErrorBody<'_>>()?;

        Ok(response.identity)
    }

    pub async fn update_module_identity(
        &self,
        module_name: &str,
    ) -> Result<Identity, std::io::Error> {
        let uri = make_uri!(
            "/identities/modules",
            self.api_version,
            ID_TYPE_AZIOT,
            module_name
        );

        let body = update_module_identity::Request {
            id_type: ID_TYPE_AZIOT.to_string(),
            module_id: module_name.to_string(),
        };

        let request = HttpRequest::put(self.connector.clone(), uri, body)
            .with_retry(self.max_retries)
            .with_timeout(self.timeout);

        let response = request.json_response().await?;
        let response: update_module_identity::Response =
            response.parse_expect_ok::<_, ErrorBody<'_>>()?;

        Ok(response.identity)
    }

    pub async fn get_identities(&self) -> Result<Vec<Identity>, std::io::Error> {
        let uri = make_uri!("/identities/modules", self.api_version, ID_TYPE_AZIOT);

        let request: HttpRequest<(), _> = HttpRequest::get(self.connector.clone(), uri)
            .with_retry(self.max_retries)
            .with_timeout(self.timeout);

        let response = request.json_response().await?;
        let response: get_module_identities::Response =
            response.parse_expect_ok::<_, ErrorBody<'_>>()?;

        Ok(response.identities)
    }

    pub async fn get_identity(&self, module_name: &str) -> Result<Identity, std::io::Error> {
        let uri = make_uri!(
            "/identities/modules",
            self.api_version,
            ID_TYPE_AZIOT,
            module_name
        );

        let request: HttpRequest<(), _> = HttpRequest::get(self.connector.clone(), uri)
            .with_retry(self.max_retries)
            .with_timeout(self.timeout);

        let response = request.json_response().await?;
        let response: get_module_identity::Response =
            response.parse_expect_ok::<_, ErrorBody<'_>>()?;

        Ok(response.identity)
    }

    pub async fn delete_identity(&self, module_name: &str) -> Result<(), std::io::Error> {
        let uri = make_uri!(
            "/identities/modules",
            self.api_version,
            ID_TYPE_AZIOT,
            module_name
        );

        let request: HttpRequest<(), _> = HttpRequest::delete(self.connector.clone(), uri, None)
            .with_retry(self.max_retries)
            .with_timeout(self.timeout);

        request.no_content_response().await
    }

    pub async fn get_trust_bundle(&self) -> Result<aziot_cert_common_http::Pem, std::io::Error> {
        let uri = make_uri!("/trust-bundle", self.api_version);

        let request: HttpRequest<(), _> = HttpRequest::get(self.connector.clone(), uri)
            .with_retry(self.max_retries)
            .with_timeout(self.timeout);

        let response = request.json_response().await?;
        let response: get_trust_bundle::Response =
            response.parse_expect_ok::<_, ErrorBody<'_>>()?;

        Ok(response.certificate)
    }
}
