// Copyright (c) Microsoft. All rights reserved.

use std::io::{Error, ErrorKind};

use aziot_identity_common_http::get_provisioning_info::Response as ProvisioningInfo;
use http_common::HttpRequest;

use crate::dps::schema;

pub struct ServerCert {
    policy: ProvisioningInfo,
    identity_cert: Vec<u8>,
    private_key: openssl::pkey::PKey<openssl::pkey::Private>,
    proxy: Option<hyper::Uri>,
}

impl ServerCert {
    #[must_use]
    pub fn new(
        policy: ProvisioningInfo,
        identity_cert: Vec<u8>,
        private_key: openssl::pkey::PKey<openssl::pkey::Private>,
    ) -> Self {
        ServerCert {
            policy,
            identity_cert,
            private_key,
            proxy: None,
        }
    }

    pub fn with_proxy(mut self, proxy: Option<hyper::Uri>) -> Self {
        self.proxy = proxy;

        self
    }

    pub async fn issue_server_cert(self, csr: openssl::x509::X509Req) -> Result<Vec<u8>, Error> {
        let (endpoint, scope_id, registation_id) = if let ProvisioningInfo::Dps {
            endpoint,
            scope_id,
            registration_id,
            ..
        } = self.policy
        {
            // TODO: fix so registration ID is always provided.
            let registration_id = registration_id.unwrap();

            let endpoint = url::Url::parse(&endpoint)
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "failed to parse DPS endpoint"))?;

            (endpoint, scope_id, registration_id)
        } else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "policy is not for DPS provisioning",
            ));
        };

        let server_cert_uri = {
            let path = format!(
                "idScope/{}/devices/{}/certificates/issue",
                scope_id, registation_id
            );

            let mut server_cert_uri = endpoint.clone();
            server_cert_uri.set_path(&path);
            server_cert_uri.set_query(Some(super::API_VERSION));

            server_cert_uri
        };

        let connector = crate::CloudConnector::new(
            self.proxy,
            Some((&self.identity_cert, &self.private_key)),
            &[],
        )?;

        todo!()
    }
}
