// Copyright (c) Microsoft. All rights reserved.

use std::sync::Arc;

use futures_util::lock::Mutex;

#[derive(Clone)]
pub(crate) struct EstIdRenewal {
    rotate_key: bool,
    credentials: aziot_certd_config::CertificateWithPrivateKey,
    api: Arc<Mutex<crate::Api>>,
}

impl EstIdRenewal {
    pub fn new(
        rotate_key: bool,
        credentials: aziot_certd_config::CertificateWithPrivateKey,
        api: Arc<Mutex<crate::Api>>,
    ) -> EstIdRenewal {
        EstIdRenewal {
            rotate_key,
            credentials,
            api,
        }
    }
}

#[async_trait::async_trait]
impl cert_renewal::CertInterface for EstIdRenewal {
    type NewKey = String;

    async fn get_cert(
        &mut self,
        cert_id: &str,
    ) -> Result<openssl::x509::X509, cert_renewal::Error> {
        let mut api = self.api.lock().await;

        let cert = api
            .get_cert(cert_id)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to retrieve cert"))?;

        openssl::x509::X509::from_pem(&cert)
            .map_err(|_| cert_renewal::Error::fatal_error("failed to parse cert"))
    }

    async fn get_key(
        &mut self,
        key_id: &str,
    ) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, cert_renewal::Error> {
        let mut api = self.api.lock().await;

        let key_handle = api
            .key_client
            .load_key_pair(key_id)
            .await
            .map_err(|_| cert_renewal::Error::retryable_error("failed to get cert key"))?;

        let key_handle = std::ffi::CString::new(key_handle.0)
            .map_err(|_| cert_renewal::Error::fatal_error("bad key handle"))?;

        api.key_engine
            .load_private_key(&key_handle)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to load cert key"))
    }

    async fn renew_cert(
        &mut self,
        old_cert: &openssl::x509::X509,
        key_id: &str,
    ) -> Result<(openssl::x509::X509, Self::NewKey), cert_renewal::Error> {
        let mut api = self.api.lock().await;

        // Get the information needed to issue an EST identity cert.
        let (url, auth) = if let Some(cert_options) =
            api.cert_issuance.certs.get(&self.credentials.cert)
        {
            if let aziot_certd_config::CertIssuanceMethod::Est { url, auth } = &cert_options.method
            {
                (url, auth)
            } else {
                return Err(cert_renewal::Error::fatal_error(
                    "EST cert issuance options not found",
                ));
            }
        } else {
            return Err(cert_renewal::Error::fatal_error(
                "failed to retrieve cert issuance options",
            ));
        };

        let (auth, url, trusted_certs) =
            crate::get_est_opts(&self.credentials.cert, &api, url, auth).map_err(|err| {
                cert_renewal::Error::fatal_error(format!(
                    "failed to get EST issuance options: {}",
                    err
                ))
            })?;

        // If the old cert is expired, authenticate with the bootstrap credentials. Otherwise,
        // use the old cert to authenticate.
        let now = openssl::asn1::Asn1Time::days_from_now(0)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to get current time"))?;

        let credentials = if old_cert.not_after() <= now {
            let auth_x509 = auth.x509.as_ref().ok_or_else(|| {
                cert_renewal::Error::fatal_error("failed to retrieve bootstrap credentials")
            })?;

            auth_x509.bootstrap_identity.as_ref().ok_or_else(|| {
                cert_renewal::Error::fatal_error("failed to retrieve bootstrap credentials")
            })?
        } else {
            &self.credentials
        };

        // Generate a new key if needed. Otherwise, retrieve the existing key.
        let (key_id, key_handle) = if self.rotate_key {
            let key_id = format!("{}-temp", key_id);

            if let Ok(key_handle) = api.key_client.load_key_pair(&key_id).await {
                api.key_client
                    .delete_key_pair(&key_handle)
                    .await
                    .map_err(|_| {
                        cert_renewal::Error::retryable_error("failed to clear temp key")
                    })?;
            }

            let key_handle = api
                .key_client
                .create_key_pair_if_not_exists(&key_id, Some("ec-p256:rsa-4096:*"))
                .await
                .map_err(|_| cert_renewal::Error::retryable_error("failed to generate temp key"))?;

            (key_id, key_handle)
        } else {
            let key_handle = api.key_client.load_key_pair(key_id).await.map_err(|_| {
                cert_renewal::Error::retryable_error("failed to get identity cert key")
            })?;

            (key_id.to_string(), key_handle)
        };

        let key_handle = std::ffi::CString::new(key_handle.0)
            .map_err(|_| cert_renewal::Error::retryable_error("bad key handle"))?;

        let private_key = api
            .key_engine
            .load_public_key(&key_handle)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to load key"))?;

        let public_key = api
            .key_engine
            .load_private_key(&key_handle)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to load key"))?;

        todo!()
    }

    async fn write_credentials(
        &mut self,
        old_cert: &openssl::x509::X509,
        new_cert: (&str, &openssl::x509::X509),
        key: (&str, Self::NewKey),
    ) -> Result<(), cert_renewal::Error> {
        todo!()
    }
}
