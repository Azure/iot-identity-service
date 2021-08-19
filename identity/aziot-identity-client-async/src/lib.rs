// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::wildcard_imports
)]

use aziot_identity_common::{Identity, ID_TYPE_AZIOT, ID_TYPE_LOCAL};

use aziot_identity_common_http::*;

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
    inner: hyper::Client<http_common::Connector, hyper::Body>,
}

impl Client {
    pub fn new(api_version: ApiVersion, connector: http_common::Connector) -> Self {
        let inner = hyper::Client::builder().build(connector);
        Client { api_version, inner }
    }

    pub async fn get_caller_identity(&self) -> Result<Identity, std::io::Error> {
        let res: get_caller_identity::Response = http_common::request::<(), _>(
            &self.inner,
            http::Method::GET,
            make_uri!("/identities/identity", self.api_version),
            None,
        )
        .await?;

        Ok(res.identity)
    }

    pub async fn get_device_identity(&self) -> Result<Identity, std::io::Error> {
        let body = get_device_identity::Request {
            id_type: ID_TYPE_AZIOT.to_string(),
        };

        let res: get_device_identity::Response = http_common::request(
            &self.inner,
            http::Method::POST,
            make_uri!("/identities/device", self.api_version),
            Some(&body),
        )
        .await?;

        Ok(res.identity)
    }

    pub async fn reprovision(&self) -> Result<(), std::io::Error> {
        let body = reprovision_device::Request {
            id_type: ID_TYPE_AZIOT.to_string(),
        };

        http_common::request_no_content(
            &self.inner,
            http::Method::POST,
            make_uri!("/device/reprovision", self.api_version),
            Some(&body),
        )
        .await?;

        Ok(())
    }

    pub async fn create_module_identity(
        &self,
        module_name: &str,
    ) -> Result<Identity, std::io::Error> {
        let body = create_module_identity::Request {
            id_type: ID_TYPE_AZIOT.to_string(),
            module_id: module_name.to_string(),
            opts: None,
        };

        let res: create_module_identity::Response = http_common::request(
            &self.inner,
            http::Method::POST,
            make_uri!("/identities/modules", self.api_version),
            Some(&body),
        )
        .await?;

        Ok(res.identity)
    }

    pub async fn create_local_identity(
        &self,
        module_name: &str,
        opts: Option<aziot_identity_common::LocalIdOpts>,
    ) -> Result<Identity, std::io::Error> {
        #[allow(clippy::redundant_closure)] // closure needed for map()
        let body = create_module_identity::Request {
            id_type: ID_TYPE_LOCAL.to_string(),
            module_id: module_name.to_string(),
            opts: opts.map(|opts| create_module_identity::CreateModuleOpts::LocalIdOpts(opts)),
        };

        let res: create_module_identity::Response = http_common::request(
            &self.inner,
            http::Method::POST,
            make_uri!("/identities/modules", self.api_version),
            Some(&body),
        )
        .await?;

        Ok(res.identity)
    }

    pub async fn update_module_identity(
        &self,
        module_name: &str,
    ) -> Result<Identity, std::io::Error> {
        let body = update_module_identity::Request {
            id_type: ID_TYPE_AZIOT.to_string(),
            module_id: module_name.to_string(),
        };

        let res: update_module_identity::Response = http_common::request(
            &self.inner,
            http::Method::PUT,
            make_uri!(
                "/identities/modules",
                self.api_version,
                ID_TYPE_AZIOT,
                module_name
            ),
            Some(&body),
        )
        .await?;

        Ok(res.identity)
    }

    pub async fn get_identities(&self) -> Result<Vec<Identity>, std::io::Error> {
        let res: get_module_identities::Response = http_common::request::<(), _>(
            &self.inner,
            http::Method::GET,
            make_uri!("/identities/modules", self.api_version, ID_TYPE_AZIOT),
            None,
        )
        .await?;

        Ok(res.identities)
    }

    pub async fn get_identity(&self, module_name: &str) -> Result<Identity, std::io::Error> {
        let res: get_module_identity::Response = http_common::request::<(), _>(
            &self.inner,
            http::Method::GET,
            make_uri!(
                "/identities/modules",
                self.api_version,
                ID_TYPE_AZIOT,
                module_name
            ),
            None,
        )
        .await?;

        Ok(res.identity)
    }

    pub async fn delete_identity(&self, module_name: &str) -> Result<(), std::io::Error> {
        http_common::request_no_content::<()>(
            &self.inner,
            http::Method::DELETE,
            make_uri!(
                "/identities/modules",
                self.api_version,
                ID_TYPE_AZIOT,
                module_name
            ),
            None,
        )
        .await?;

        Ok(())
    }

    pub async fn get_trust_bundle(&self) -> Result<aziot_cert_common_http::Pem, std::io::Error> {
        let res: get_trust_bundle::Response = http_common::request::<(), _>(
            &self.inner,
            http::Method::GET,
            make_uri!("/trust-bundle", self.api_version),
            None,
        )
        .await?;

        Ok(res.certificate)
    }
}
