// Copyright (c) Microsoft. All rights reserved.

mod schema;

use std::io::{Error, ErrorKind};

use aziot_identity_common_http::get_provisioning_info::Response as ProvisioningInfo;
use http_common::HttpRequest;

pub struct IssueCert {
    policy: ProvisioningInfo,
    identity_cert: Vec<u8>,
    private_key: openssl::pkey::PKey<openssl::pkey::Private>,
    proxy: Option<hyper::Uri>,
}

impl IssueCert {
    #[must_use]
    pub fn new(
        policy: ProvisioningInfo,
        identity_cert: Vec<u8>,
        private_key: openssl::pkey::PKey<openssl::pkey::Private>,
    ) -> Self {
        IssueCert {
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

    #[allow(clippy::too_many_lines)]
    pub async fn issue_server_cert(self, csr: openssl::x509::X509Req) -> Result<Vec<u8>, Error> {
        let (endpoint, scope_id, registation_id) = if let ProvisioningInfo::Dps {
            endpoint,
            scope_id,
            registration_id,
            ..
        } = self.policy
        {
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
            let path = format!("{}/devices/{}/certificates/issue", scope_id, registation_id);

            let mut server_cert_uri = endpoint.clone();
            server_cert_uri.set_path(&path);
            server_cert_uri.set_query(Some(super::API_VERSION));

            server_cert_uri
        };

        let body = {
            let csr = csr
                .to_der()
                .map_err(|err| Error::new(ErrorKind::InvalidInput, err))?;
            let csr = base64::encode(csr);

            schema::request::IssueCert {
                cert_type: aziot_identity_common::CertType::Server,
                csr,
            }
        };

        let connector = crate::CloudConnector::new(
            self.proxy,
            Some((&self.identity_cert, &self.private_key)),
            &[],
        )?;

        log::info!("Sending DPS server cert request.");
        let request = HttpRequest::post(connector.clone(), server_cert_uri.as_str(), Some(body));
        let response = request.json_response().await?;

        let operation_id = {
            let response = response.parse::<super::OperationStatus, super::ServiceError>(&[
                hyper::StatusCode::OK,
                hyper::StatusCode::ACCEPTED,
            ])?;

            response.operation_id
        };

        let operation_uri = {
            let path = format!(
                "{}/devices/{}/operations/{}",
                scope_id, registation_id, operation_id
            );

            let mut operation_uri = endpoint.clone();
            operation_uri.set_path(&path);
            operation_uri.set_query(Some(super::API_VERSION));

            operation_uri
        };

        // Query the operation status until certificate issuance finishes.
        tokio::time::sleep(super::POLL_PERIOD).await;

        let cert_uri = loop {
            let request: HttpRequest<(), _> =
                HttpRequest::get(connector.clone(), operation_uri.as_str());

            log::info!("Checking status of DPS server cert request.");
            let response = request.json_response().await?;

            let response = response
                .parse::<schema::response::CertRequestStatus, super::ServiceError>(&[
                    hyper::StatusCode::OK,
                    hyper::StatusCode::ACCEPTED,
                ])?;

            match response.status {
                schema::RequestStatus::Succeeded => {
                    let mut uri = url::Url::parse(&response.uri).map_err(|_| {
                        Error::new(
                            ErrorKind::InvalidData,
                            "failed to parse DPS certificate URI",
                        )
                    })?;
                    uri.set_query(Some(super::API_VERSION));

                    log::info!("DPS server certificate issued. Retrieving certificate.");

                    break uri;
                }

                schema::RequestStatus::NotStarted | schema::RequestStatus::Running => {
                    log::info!("DPS server cert request is still in progress.");

                    tokio::time::sleep(super::POLL_PERIOD).await;
                }

                _ => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "DPS server cert request returned status {}",
                            response.status
                        ),
                    ));
                }
            }
        };

        // Get the issued certificate.
        let request: HttpRequest<(), _> = HttpRequest::get(connector, cert_uri.as_str());
        let response = request.json_response().await?;

        let response =
            response.parse_expect_ok::<schema::response::Certificate, super::ServiceError>()?;

        response.try_into()
    }
}
