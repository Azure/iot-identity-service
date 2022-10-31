// Copyright (c) Microsoft. All rights reserved.

use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct IdentityCertRenewal {
    rotate_key: bool,
    temp_cert: String,

    api: Arc<futures_util::lock::Mutex<crate::Api>>,
    cert_client: Arc<aziot_cert_client_async::Client>,
    key_client: Arc<aziot_key_client_async::Client>,
    key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
}

impl IdentityCertRenewal {
    pub async fn new(
        rotate_key: bool,
        cert_id: &str,
        key_id: &str,
        registration_id: Option<&aziot_identityd_config::CsrSubject>,
        api: Arc<futures_util::lock::Mutex<crate::Api>>,
    ) -> Result<Self, crate::Error> {
        let (cert_client, key_client, key_engine) = {
            let api = api.lock().await;

            (
                api.cert_client.clone(),
                api.key_client.clone(),
                api.key_engine.clone(),
            )
        };

        // Create the initial identity certificate if it does not exist.
        if cert_client.get_cert(cert_id).await.is_err() {
            let registration_id = if let Some(registration_id) = registration_id {
                registration_id
            } else {
                return Err(crate::Error::Internal(
                    crate::InternalError::CreateCertificate(
                        "identity cert does not exist; cannot create new cert as registration ID is unknown".into()
                    ),
                ));
            };

            if let Ok(key_handle) = key_client.load_key_pair(key_id).await {
                key_client
                    .delete_key_pair(&key_handle)
                    .await
                    .map_err(|err| {
                        crate::Error::Internal(crate::InternalError::CreateCertificate(
                            format!("failed to remove old key: {}", err).into(),
                        ))
                    })?;
            }

            let key_handle = key_client
                .create_key_pair_if_not_exists(key_id, Some("rsa-2048:*"))
                .await
                .map_err(|err| {
                    crate::Error::Internal(crate::InternalError::CreateCertificate(
                        format!("failed to generate new key: {}", err).into(),
                    ))
                })?;

            let (private_key, public_key) = crate::get_keys(key_handle, &key_engine)
                .await
                .map_err(|err| {
                    crate::Error::Internal(crate::InternalError::CreateCertificate(err.into()))
                })?;

            let subject = openssl::x509::X509Name::try_from(registration_id).map_err(|err| {
                crate::Error::Internal(crate::InternalError::CreateCertificate(err.into()))
            })?;
            let csr =
                crate::create_csr(&subject, &public_key, &private_key, None).map_err(|_| {
                    crate::Error::Internal(crate::InternalError::CreateCertificate(
                        "failed to generate csr".into(),
                    ))
                })?;

            cert_client
                .create_cert(cert_id, &csr, None)
                .await
                .map_err(|err| {
                    crate::Error::Internal(crate::InternalError::CreateCertificate(err.into()))
                })?;

            log::info!("Generated initial device identity certificate.");
        }

        // Determine the temporary cert ID used during renewal. Identity Service must be authorized
        // to modify this cert with Certificates Service.
        let temp_cert = format!("{}-temp", cert_id);

        Ok(IdentityCertRenewal {
            rotate_key,
            temp_cert,
            api,
            cert_client,
            key_client,
            key_engine,
        })
    }
}

#[async_trait::async_trait]
impl cert_renewal::CertInterface for IdentityCertRenewal {
    type NewKey = String;

    async fn get_cert(
        &mut self,
        cert_id: &str,
    ) -> Result<Vec<openssl::x509::X509>, cert_renewal::Error> {
        let cert = self.cert_client.get_cert(cert_id).await.map_err(|_| {
            cert_renewal::Error::retryable_error("failed to retrieve identity cert")
        })?;

        let cert_chain = openssl::x509::X509::stack_from_pem(&cert)
            .map_err(|_| cert_renewal::Error::fatal_error("failed to parse identity cert"))?;

        if cert_chain.is_empty() {
            Err(cert_renewal::Error::fatal_error("no certs in cert chain"))
        } else {
            Ok(cert_chain)
        }
    }

    async fn get_key(
        &mut self,
        key_id: &str,
    ) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, cert_renewal::Error> {
        let key_handle =
            self.key_client.load_key_pair(key_id).await.map_err(|_| {
                cert_renewal::Error::retryable_error("failed to get identity cert key")
            })?;

        let key_handle = std::ffi::CString::new(key_handle.0)
            .map_err(|_| cert_renewal::Error::fatal_error("bad key handle"))?;

        let mut key_engine = self.key_engine.lock().await;

        key_engine
            .load_private_key(&key_handle)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to load identity cert key"))
    }

    async fn renew_cert(
        &mut self,
        old_cert_chain: &[openssl::x509::X509],
        key_id: &str,
    ) -> Result<(Vec<openssl::x509::X509>, Self::NewKey), cert_renewal::Error> {
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
                .create_key_pair_if_not_exists(&key_id, Some("rsa-2048:*"))
                .await
                .map_err(|_| cert_renewal::Error::retryable_error("failed to generate temp key"))?;

            (key_id, key_handle)
        } else {
            let key_handle = self.key_client.load_key_pair(key_id).await.map_err(|_| {
                cert_renewal::Error::retryable_error("failed to get identity cert key")
            })?;

            (key_id.to_string(), key_handle)
        };

        let (private_key, public_key) = crate::get_keys(key_handle, &self.key_engine)
            .await
            .map_err(cert_renewal::Error::retryable_error)?;

        // Determine the subject of the old cert. This will be the subject of the new cert.
        let subject = old_cert_chain[0].subject_name();

        // Generate a CSR and issue the new cert under a temporary cert ID. The temporary ID
        // does not need to be persisted, so delete it after the cert is succesfully created.
        let csr = crate::create_csr(subject, &public_key, &private_key, None)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to create csr"))?;

        let new_cert = self
            .cert_client
            .create_cert(&self.temp_cert, &csr, None)
            .await
            .map_err(|_| cert_renewal::Error::retryable_error("failed to create new cert"))?;

        if let Err(err) = self.cert_client.delete_cert(&self.temp_cert).await {
            log::warn!(
                "Failed to delete temporary certificate created by cert renewal: {}",
                err
            );
        }

        let new_cert_chain = openssl::x509::X509::stack_from_pem(&new_cert)
            .map_err(|_| cert_renewal::Error::retryable_error("failed to parse new cert"))?;

        if new_cert_chain.is_empty() {
            Err(cert_renewal::Error::retryable_error(
                "no certs in cert chain",
            ))
        } else {
            Ok((new_cert_chain, key_id))
        }
    }

    async fn write_credentials(
        &mut self,
        _old_cert_chain: &[openssl::x509::X509],
        new_cert_chain: (&str, &[openssl::x509::X509]),
        key: (&str, Self::NewKey),
    ) -> Result<(), cert_renewal::Error> {
        let (cert_id, new_cert_chain) = (new_cert_chain.0, new_cert_chain.1);
        let (old_key, new_key) = (key.0, key.1);

        if new_cert_chain.is_empty() {
            return Err(cert_renewal::Error::retryable_error(
                "no certs in cert chain",
            ));
        }

        let mut new_cert_chain_pem = Vec::new();

        for cert in new_cert_chain {
            let mut cert = cert
                .to_pem()
                .map_err(|_| cert_renewal::Error::retryable_error("bad cert"))?;

            new_cert_chain_pem.append(&mut cert);
        }

        let new_key_handle =
            self.key_client.load_key_pair(&new_key).await.map_err(|_| {
                cert_renewal::Error::retryable_error("failed to get new key handle")
            })?;

        // Reprovision the device to register the new cert with DPS.
        let (private_key, _) = crate::get_keys(new_key_handle, &self.key_engine)
            .await
            .map_err(|_| cert_renewal::Error::retryable_error("failed to get cert key"))?;

        let credentials = aziot_identity_common::Credentials::X509 {
            identity_cert: (cert_id.to_string(), new_cert_chain.to_vec()),
            identity_pk: (new_key.clone(), private_key),
        };

        let mut api = self.api.lock().await;

        api.reprovision_device(
            crate::auth::AuthId::LocalRoot,
            crate::ReprovisionTrigger::Api,
            Some(credentials),
        )
        .await
        .map_err(|err| {
            cert_renewal::Error::retryable_error(format!(
                "failed to reprovision with new credentials: {}",
                err
            ))
        })?;

        // Note that if any of the operations below fail, the device will be left in an error state
        // as it has already been reprovisioned with the new credentials in DPS.

        // Commit the new cert to storage.
        let cert = self
            .cert_client
            .import_cert(cert_id, &new_cert_chain_pem)
            .await
            .map_err(|_| cert_renewal::Error::retryable_error("failed to import new cert"))?;

        let cert = openssl::x509::X509::stack_from_pem(&cert)
            .map_err(|_| cert_renewal::Error::retryable_error("bad cert"))?;

        // Commit the new key to storage if the key was rotated.
        if old_key != new_key {
            self.key_client
                .move_key_pair(&new_key, old_key)
                .await
                .map_err(|_| cert_renewal::Error::retryable_error("failed to import new key"))?;
        }

        // Reload the device credentials with the updated credentials.
        let key_handle =
            self.key_client.load_key_pair(old_key).await.map_err(|_| {
                cert_renewal::Error::retryable_error("failed to get new key handle")
            })?;

        let (private_key, _) = crate::get_keys(key_handle, &self.key_engine)
            .await
            .map_err(|_| cert_renewal::Error::retryable_error("failed to get cert key"))?;

        let credentials = aziot_identity_common::Credentials::X509 {
            identity_cert: (cert_id.to_string(), cert),
            identity_pk: (old_key.to_string(), private_key),
        };

        if let Some(device) = &mut api.id_manager.iot_hub_device {
            device.credentials = credentials;
        };

        Ok(())
    }
}
