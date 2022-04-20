// Copyright (c) Microsoft. All rights reserved.

#[derive(Clone)]
pub(crate) struct EstIdRenewal {
    rotate_key: bool,
    credentials: aziot_certd_config::CertificateWithPrivateKey,
    path: std::path::PathBuf,
    url: url::Url,
    auth: aziot_certd_config::EstAuth,
    key_client: std::sync::Arc<aziot_key_client_async::Client>,
    key_engine: std::sync::Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
}

impl EstIdRenewal {
    pub async fn new(
        credentials: aziot_certd_config::CertificateWithPrivateKey,
        api: &crate::Api,
    ) -> Result<EstIdRenewal, crate::Error> {
        let path = aziot_certd_config::util::get_path(
            &api.homedir_path,
            &api.preloaded_certs,
            &credentials.cert,
            false,
        )
        .map_err(|err| crate::Error::Internal(crate::InternalError::GetPath(err)))?;

        let (auth, url) = crate::get_est_opts(&credentials.cert, api)
            .map_err(|err| crate::Error::invalid_parameter("cert_id", err))?;

        let rotate_key = {
            let est_config = api.est_config.read().await;

            est_config.renewal.rotate_key
        };

        Ok(EstIdRenewal {
            rotate_key,
            credentials,
            path,
            url,
            auth,
            key_client: api.key_client.clone(),
            key_engine: api.key_engine.clone(),
        })
    }
}

#[async_trait::async_trait]
impl cert_renewal::CertInterface for EstIdRenewal {
    type NewKey = String;

    async fn get_cert(
        &mut self,
        cert_id: &str,
    ) -> Result<openssl::x509::X509, cert_renewal::Error> {
        let cert = std::fs::read(&self.path).map_err(|err| {
            cert_renewal::Error::retryable_error(format!("failed to read cert: {}", err))
        })?;

        openssl::x509::X509::from_pem(&cert)
            .map_err(|_| cert_renewal::Error::fatal_error("failed to parse cert"))
    }

    async fn get_key(
        &mut self,
        key_id: &str,
    ) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, cert_renewal::Error> {
        let key_handle = self
            .key_client
            .load_key_pair(key_id)
            .await
            .map_err(|_| cert_renewal::Error::retryable_error("failed to get cert key"))?;

        let key_handle = std::ffi::CString::new(key_handle.0)
            .map_err(|_| cert_renewal::Error::fatal_error("bad key handle"))?;

        let mut key_engine = self.key_engine.lock().await;

        key_engine
            .load_private_key(&key_handle)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to load cert key"))
    }

    async fn renew_cert(
        &mut self,
        old_cert: &openssl::x509::X509,
        key_id: &str,
    ) -> Result<(openssl::x509::X509, Self::NewKey), cert_renewal::Error> {
        // Get the information needed to issue an EST identity cert.
        // let (url, auth) = if let Some(cert_options) =
        //     api.cert_issuance.certs.get(&self.credentials.cert)
        // {
        //     if let aziot_certd_config::CertIssuanceMethod::Est { url, auth } = &cert_options.method
        //     {
        //         (url, auth)
        //     } else {
        //         return Err(cert_renewal::Error::fatal_error(
        //             "EST cert issuance options not found",
        //         ));
        //     }
        // } else {
        //     return Err(cert_renewal::Error::fatal_error(
        //         "failed to retrieve cert issuance options",
        //     ));
        // };

        // let (auth, url, trusted_certs) =
        //     crate::get_est_opts(&self.credentials.cert, &api, url, auth).map_err(|err| {
        //         cert_renewal::Error::fatal_error(format!(
        //             "failed to get EST issuance options: {}",
        //             err
        //         ))
        //     })?;

        // // If the old cert is expired, authenticate with the bootstrap credentials. Otherwise,
        // // use the old cert to authenticate.
        // let now = openssl::asn1::Asn1Time::days_from_now(0)
        //     .map_err(|_| cert_renewal::Error::retryable_error("failed to get current time"))?;

        // let credentials = if old_cert.not_after() <= now {
        //     let auth_x509 = auth.x509.as_ref().ok_or_else(|| {
        //         cert_renewal::Error::fatal_error("failed to retrieve bootstrap credentials")
        //     })?;

        //     auth_x509.bootstrap_identity.as_ref().ok_or_else(|| {
        //         cert_renewal::Error::fatal_error("failed to retrieve bootstrap credentials")
        //     })?
        // } else {
        //     &self.credentials
        // };

        // // Generate a new key if needed. Otherwise, retrieve the existing key.
        // let (key_id, key_handle) = if self.rotate_key {
        //     let key_id = format!("{}-temp", key_id);

        //     if let Ok(key_handle) = api.key_client.load_key_pair(&key_id).await {
        //         api.key_client
        //             .delete_key_pair(&key_handle)
        //             .await
        //             .map_err(|_| {
        //                 cert_renewal::Error::retryable_error("failed to clear temp key")
        //             })?;
        //     }

        //     let key_handle = api
        //         .key_client
        //         .create_key_pair_if_not_exists(&key_id, Some("ec-p256:rsa-4096:*"))
        //         .await
        //         .map_err(|_| cert_renewal::Error::retryable_error("failed to generate temp key"))?;

        //     (key_id, key_handle)
        // } else {
        //     let key_handle = api.key_client.load_key_pair(key_id).await.map_err(|_| {
        //         cert_renewal::Error::retryable_error("failed to get identity cert key")
        //     })?;

        //     (key_id.to_string(), key_handle)
        // };

        // let key_handle = std::ffi::CString::new(key_handle.0)
        //     .map_err(|_| cert_renewal::Error::retryable_error("bad key handle"))?;

        // let private_key = api
        //     .key_engine
        //     .load_public_key(&key_handle)
        //     .map_err(|_| cert_renewal::Error::retryable_error("failed to load key"))?;

        // let public_key = api
        //     .key_engine
        //     .load_private_key(&key_handle)
        //     .map_err(|_| cert_renewal::Error::retryable_error("failed to load key"))?;

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
