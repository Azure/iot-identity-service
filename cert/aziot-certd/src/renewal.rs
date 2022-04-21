// Copyright (c) Microsoft. All rights reserved.

#[derive(Clone)]
pub(crate) struct EstIdRenewal {
    rotate_key: bool,
    credentials: aziot_certd_config::CertificateWithPrivateKey,
    path: std::path::PathBuf,
    bootstrap_path: Option<(std::path::PathBuf, String)>,
    url: url::Url,
    basic_auth: Option<aziot_certd_config::EstAuthBasic>,
    key_client: std::sync::Arc<aziot_key_client_async::Client>,
    key_engine: std::sync::Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
    est_config: std::sync::Arc<tokio::sync::RwLock<crate::est::EstConfig>>,
}

impl EstIdRenewal {
    pub async fn new(
        cert_id: &str,
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

        let (auth, url) = crate::get_est_opts(cert_id, api, None)
            .map_err(|err| crate::Error::invalid_parameter("cert_id", err))?;

        let bootstrap_path = if let Some(x509) = &auth.x509 {
            if let Some(bootstrap) = &x509.bootstrap_identity {
                let bootstrap_path = aziot_certd_config::util::get_path(
                    &api.homedir_path,
                    &api.preloaded_certs,
                    &bootstrap.cert,
                    false,
                )
                .map_err(|err| crate::Error::Internal(crate::InternalError::GetPath(err)))?;

                Some((bootstrap_path, bootstrap.pk.to_string()))
            } else {
                None
            }
        } else {
            None
        };

        let rotate_key = {
            let est_config = api.est_config.read().await;

            est_config.renewal.rotate_key
        };

        Ok(EstIdRenewal {
            rotate_key,
            credentials,
            path,
            bootstrap_path,
            url,
            basic_auth: auth.basic,
            key_client: api.key_client.clone(),
            key_engine: api.key_engine.clone(),
            est_config: api.est_config.clone(),
        })
    }

    async fn load_keys(
        &self,
        key_handle: aziot_key_common::KeyHandle,
    ) -> Result<
        (
            openssl::pkey::PKey<openssl::pkey::Private>,
            openssl::pkey::PKey<openssl::pkey::Public>,
        ),
        cert_renewal::Error,
    > {
        let key_handle = std::ffi::CString::new(key_handle.0)
            .map_err(|_| cert_renewal::Error::retryable_error("bad key handle"))?;

        let mut key_engine = self.key_engine.lock().await;

        let private_key = key_engine
            .load_private_key(&key_handle)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to load key"))?;

        let public_key = key_engine
            .load_public_key(&key_handle)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to load key"))?;

        Ok((private_key, public_key))
    }
}

#[async_trait::async_trait]
impl cert_renewal::CertInterface for EstIdRenewal {
    type NewKey = String;

    #[allow(clippy::unused_async)]
    async fn get_cert(
        &mut self,
        _cert_id: &str,
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
        // If the old cert is expired, authenticate with the bootstrap credentials. Otherwise,
        // use the old cert to authenticate.
        let now = openssl::asn1::Asn1Time::days_from_now(0)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to get current time"))?;

        let (est_id_cert, est_id_key) = if old_cert.not_after() <= now {
            if let Some((bootstrap_path, bootstrap_key)) = &self.bootstrap_path {
                let bootstrap_cert = std::fs::read(bootstrap_path).map_err(|_| {
                    cert_renewal::Error::retryable_error("failed to read bootstrap cert")
                })?;

                (bootstrap_cert, bootstrap_key)
            } else {
                return Err(cert_renewal::Error::fatal_error(
                    "bootstrap credentials not available",
                ));
            }
        } else {
            let cert = old_cert
                .to_pem()
                .map_err(|_| cert_renewal::Error::fatal_error("bad cert"))?;

            (cert, &self.credentials.pk)
        };

        let est_id_key = self
            .key_client
            .load_key_pair(est_id_key)
            .await
            .map_err(|_| cert_renewal::Error::retryable_error("failed to load EST auth key"))?;

        let (est_id_key, _) = self
            .load_keys(est_id_key)
            .await
            .map_err(|_| cert_renewal::Error::retryable_error("failed to load EST auth key"))?;

        // Generate a new key if needed. Otherwise, retrieve the existing key.
        let (key_id, key_handle) = if self.rotate_key {
            let key_id = format!("{}-temp", key_id);

            if let Ok(key_handle) = self.key_client.load_key_pair(&key_id).await {
                self.key_client
                    .delete_key_pair(&key_handle)
                    .await
                    .map_err(|_| {
                        cert_renewal::Error::retryable_error("failed to clear temp key")
                    })?;
            }

            let key_handle = self
                .key_client
                .create_key_pair_if_not_exists(&key_id, Some("ec-p256:rsa-4096:*"))
                .await
                .map_err(|_| cert_renewal::Error::retryable_error("failed to generate temp key"))?;

            (key_id, key_handle)
        } else {
            let key_handle = self.key_client.load_key_pair(key_id).await.map_err(|_| {
                cert_renewal::Error::retryable_error("failed to get identity cert key")
            })?;

            (key_id.to_string(), key_handle)
        };

        let keys = self.load_keys(key_handle).await?;

        let cert = {
            let est_config = self.est_config.read().await;

            crate::create_est_id(
                old_cert.subject_name(),
                keys,
                &self.url,
                (est_id_cert, est_id_key),
                self.basic_auth.as_ref(),
                &est_config.trusted_certs,
                est_config.proxy_uri.clone(),
            )
            .await
            .map_err(|err| {
                cert_renewal::Error::retryable_error(format!(
                    "failed to issue new EST identity cert: {}",
                    err
                ))
            })?
        };

        let cert = openssl::x509::X509::from_pem(&cert)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to parse new cert"))?;

        Ok((cert, key_id))
    }

    async fn write_credentials(
        &mut self,
        old_cert: &openssl::x509::X509,
        new_cert: (&str, &openssl::x509::X509),
        key: (&str, Self::NewKey),
    ) -> Result<(), cert_renewal::Error> {
        let new_cert = new_cert.1;
        let (old_key, new_key) = (key.0, key.1);

        let new_cert_pem = new_cert
            .to_pem()
            .map_err(|_| cert_renewal::Error::retryable_error("bad cert"))?;

        let old_cert_pem = old_cert
            .to_pem()
            .map_err(|_| cert_renewal::Error::retryable_error("bad cert"))?;

        // Commit the new cert to storage.
        std::fs::write(&self.path, &new_cert_pem)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to import new cert"))?;

        // Commit the new key to storage if the key was rotated.
        if old_key != new_key
            && self
                .key_client
                .move_key_pair(&new_key, old_key)
                .await
                .is_err()
        {
            // Revert to the previous cert if the key could not be written.
            std::fs::write(&self.path, &old_cert_pem)
                .map_err(|_| cert_renewal::Error::retryable_error("failed to restore old cert"))?;
        }

        Ok(())
    }
}
