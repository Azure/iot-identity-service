// Copyright (c) Microsoft. All rights reserved.

use std::path::Path;
use std::sync::Arc;

use aziot_identityd_config as config;

use crate::create_csr;
use crate::error::{Error, InternalError};

const IOTHUB_ENCODE_SET: &percent_encoding::AsciiSet =
    &http_common::PATH_SEGMENT_ENCODE_SET.add(b'=');

pub struct IdentityManager {
    locks: std::sync::Mutex<std::collections::BTreeMap<String, Arc<std::sync::Mutex<()>>>>,
    homedir_path: std::path::PathBuf,
    key_client: Arc<aziot_key_client_async::Client>,
    key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
    cert_client: Arc<aziot_cert_client_async::Client>,
    tpm_client: Arc<aziot_tpm_client_async::Client>,
    iot_hub_device: Option<aziot_identity_common::IoTHubDevice>,
    proxy_uri: Option<hyper::Uri>,
}

impl IdentityManager {
    pub fn new(
        homedir_path: std::path::PathBuf,
        key_client: Arc<aziot_key_client_async::Client>,
        key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
        cert_client: Arc<aziot_cert_client_async::Client>,
        tpm_client: Arc<aziot_tpm_client_async::Client>,
        iot_hub_device: Option<aziot_identity_common::IoTHubDevice>,
        proxy_uri: Option<hyper::Uri>,
    ) -> Self {
        IdentityManager {
            locks: Default::default(),
            homedir_path,
            key_client,
            key_engine,
            cert_client,
            tpm_client,
            iot_hub_device, //set by Server over futures channel
            proxy_uri,
        }
    }

    pub fn set_device(&mut self, device: &aziot_identity_common::IoTHubDevice) {
        self.iot_hub_device = Some(device.clone());
    }

    pub async fn create_module_identity(
        &self,
        module_id: &str,
    ) -> Result<aziot_identity_common::Identity, Error> {
        if module_id.trim().is_empty() {
            return Err(Error::invalid_parameter(
                "module_id",
                "module name cannot be empty",
            ));
        }

        match &self.iot_hub_device {
            Some(device) => {
                let client = aziot_hub_client_async::Client::new(
                    device.clone(),
                    self.key_client.clone(),
                    self.key_engine.clone(),
                    self.cert_client.clone(),
                    self.tpm_client.clone(),
                    self.proxy_uri.clone(),
                );
                let new_module = client
                    .create_module(&*module_id, None, None)
                    .await
                    .map_err(Error::HubClient)?;

                let master_id_key_handle = self.get_master_identity_key().await?;
                let (primary_key_handle, _, primary_key, secondary_key) = self
                    .get_module_derived_keys(master_id_key_handle, new_module.clone())
                    .await?;
                let module_credentials =
                    aziot_identity_common::Credentials::SharedPrivateKey(primary_key_handle.0);

                let response = client
                    .update_module(
                        &*new_module.module_id,
                        Some(aziot_identity_common::hub::AuthMechanism {
                            symmetric_key: Some(aziot_identity_common::hub::SymmetricKey {
                                primary_key: Some(http_common::ByteString(primary_key)),
                                secondary_key: Some(http_common::ByteString(secondary_key)),
                            }),
                            x509_thumbprint: None,
                            type_: Some(aziot_identity_common::hub::AuthType::Sas),
                        }),
                        None,
                    )
                    .await
                    .map_err(Error::HubClient)?;

                let identity =
                    aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
                        hub_name: device.iothub_hostname.clone(),
                        device_id: aziot_identity_common::DeviceId(response.device_id),
                        module_id: Some(aziot_identity_common::ModuleId(response.module_id)),
                        gen_id: response.generation_id.map(aziot_identity_common::GenId),
                        auth: Some(aziot_identity_common::AuthenticationInfo::from(
                            module_credentials,
                        )),
                    });
                Ok(identity)
            }
            None => Err(Error::DeviceNotFound),
        }
    }

    pub async fn update_module_identity(
        &self,
        module_id: &str,
    ) -> Result<aziot_identity_common::Identity, Error> {
        if module_id.trim().is_empty() {
            return Err(Error::invalid_parameter(
                "module_id",
                "module name cannot be empty",
            ));
        }

        match &self.iot_hub_device {
            Some(device) => {
                let client = aziot_hub_client_async::Client::new(
                    device.clone(),
                    self.key_client.clone(),
                    self.key_engine.clone(),
                    self.cert_client.clone(),
                    self.tpm_client.clone(),
                    self.proxy_uri.clone(),
                );
                let curr_module = client
                    .get_module(&*module_id)
                    .await
                    .map_err(Error::HubClient)?;

                let master_id_key_handle = self.get_master_identity_key().await?;
                let (primary_key_handle, _, primary_key, secondary_key) = self
                    .get_module_derived_keys(master_id_key_handle, curr_module.clone())
                    .await?;
                let module_credentials =
                    aziot_identity_common::Credentials::SharedPrivateKey(primary_key_handle.0);

                let response = client
                    .update_module(
                        &*curr_module.module_id,
                        Some(aziot_identity_common::hub::AuthMechanism {
                            symmetric_key: Some(aziot_identity_common::hub::SymmetricKey {
                                primary_key: Some(http_common::ByteString(primary_key)),
                                secondary_key: Some(http_common::ByteString(secondary_key)),
                            }),
                            x509_thumbprint: None,
                            type_: Some(aziot_identity_common::hub::AuthType::Sas),
                        }),
                        None,
                    )
                    .await
                    .map_err(Error::HubClient)?;

                let identity =
                    aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
                        hub_name: device.iothub_hostname.clone(),
                        device_id: aziot_identity_common::DeviceId(response.device_id),
                        module_id: Some(aziot_identity_common::ModuleId(response.module_id)),
                        gen_id: response.generation_id.map(aziot_identity_common::GenId),
                        auth: Some(aziot_identity_common::AuthenticationInfo::from(
                            module_credentials,
                        )),
                    });
                Ok(identity)
            }
            None => Err(Error::DeviceNotFound),
        }
    }

    pub async fn get_device_identity(&self) -> Result<aziot_identity_common::Identity, Error> {
        match &self.iot_hub_device {
            Some(device) => Ok(aziot_identity_common::Identity::Aziot(
                aziot_identity_common::AzureIoTSpec {
                    hub_name: device.iothub_hostname.clone(),
                    device_id: aziot_identity_common::DeviceId(device.device_id.clone()),
                    module_id: None,
                    gen_id: None,
                    auth: Some(self.get_device_identity_key().await?),
                },
            )),
            None => Err(Error::DeviceNotFound),
        }
    }

    pub async fn get_module_identity(
        &self,
        module_id: &str,
    ) -> Result<aziot_identity_common::Identity, Error> {
        if module_id.trim().is_empty() {
            return Err(Error::invalid_parameter(
                "module_id",
                "module name cannot be empty",
            ));
        }

        match &self.iot_hub_device {
            Some(device) => {
                let client = aziot_hub_client_async::Client::new(
                    device.clone(),
                    self.key_client.clone(),
                    self.key_engine.clone(),
                    self.cert_client.clone(),
                    self.tpm_client.clone(),
                    self.proxy_uri.clone(),
                );
                let module = client
                    .get_module(&*module_id)
                    .await
                    .map_err(Error::HubClient)?;

                let master_id_key_handle = self.get_master_identity_key().await?;
                let (primary_key_handle, _, _, _) = self
                    .get_module_derived_keys(master_id_key_handle, module.clone())
                    .await?;
                let module_credentials =
                    aziot_identity_common::Credentials::SharedPrivateKey(primary_key_handle.0);

                let identity =
                    aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
                        hub_name: device.iothub_hostname.clone(),
                        device_id: aziot_identity_common::DeviceId(module.device_id),
                        module_id: Some(aziot_identity_common::ModuleId(module.module_id)),
                        gen_id: module.generation_id.map(aziot_identity_common::GenId),
                        auth: Some(aziot_identity_common::AuthenticationInfo::from(
                            module_credentials,
                        )),
                    });

                Ok(identity)
            }
            None => Err(Error::DeviceNotFound),
        }
    }

    pub async fn get_module_identities(
        &self,
    ) -> Result<Vec<aziot_identity_common::Identity>, Error> {
        match &self.iot_hub_device {
            Some(device) => {
                let client = aziot_hub_client_async::Client::new(
                    device.clone(),
                    self.key_client.clone(),
                    self.key_engine.clone(),
                    self.cert_client.clone(),
                    self.tpm_client.clone(),
                    self.proxy_uri.clone(),
                );

                let response = client.get_modules().await.map_err(Error::HubClient)?;

                let identities = response
                    .into_iter()
                    .map(|module| {
                        aziot_identity_common::Identity::Aziot(
                            aziot_identity_common::AzureIoTSpec {
                                hub_name: device.iothub_hostname.clone(),
                                device_id: aziot_identity_common::DeviceId(module.device_id),
                                module_id: Some(aziot_identity_common::ModuleId(module.module_id)),
                                gen_id: module.generation_id.map(aziot_identity_common::GenId),
                                auth: None, //Auth information can be requested via get_module_identity
                            },
                        )
                    })
                    .collect();
                Ok(identities)
            }
            None => Err(Error::DeviceNotFound),
        }
    }

    pub async fn delete_module_identity(&self, module_id: &str) -> Result<(), Error> {
        if module_id.trim().is_empty() {
            return Err(Error::invalid_parameter(
                "module_id",
                "module name cannot be empty",
            ));
        }

        match &self.iot_hub_device {
            Some(device) => {
                let client = aziot_hub_client_async::Client::new(
                    device.clone(),
                    self.key_client.clone(),
                    self.key_engine.clone(),
                    self.cert_client.clone(),
                    self.tpm_client.clone(),
                    self.proxy_uri.clone(),
                );
                client
                    .delete_module(&*module_id)
                    .await
                    .map_err(Error::HubClient)
            }
            None => Err(Error::DeviceNotFound),
        }
    }

    async fn get_device_identity_key(
        &self,
    ) -> Result<aziot_identity_common::AuthenticationInfo, Error> {
        match &self.iot_hub_device {
            Some(device) => match &device.credentials {
                aziot_identity_common::Credentials::SharedPrivateKey(key) => {
                    let key_handle = self
                        .key_client
                        .load_key(key.as_str())
                        .await
                        .map_err(Error::KeyClient)?;
                    Ok(aziot_identity_common::AuthenticationInfo {
                        auth_type: aziot_identity_common::AuthenticationType::Sas,
                        key_handle: Some(aziot_key_common::KeyHandle(key_handle.0)),
                        cert_id: None,
                    })
                }
                aziot_identity_common::Credentials::X509 {
                    identity_cert,
                    identity_pk,
                } => {
                    let identity_pk_key_handle = self
                        .key_client
                        .load_key_pair(identity_pk.as_str())
                        .await
                        .map_err(Error::KeyClient)?;
                    Ok(aziot_identity_common::AuthenticationInfo {
                        auth_type: aziot_identity_common::AuthenticationType::X509,
                        key_handle: Some(aziot_key_common::KeyHandle(identity_pk_key_handle.0)),
                        cert_id: Some(identity_cert.clone()),
                    })
                }
                aziot_identity_common::Credentials::Tpm => {
                    Ok(aziot_identity_common::AuthenticationInfo {
                        auth_type: aziot_identity_common::AuthenticationType::Tpm,
                        key_handle: None,
                        cert_id: None,
                    })
                }
            },
            None => Err(Error::DeviceNotFound),
        }
    }

    async fn get_master_identity_key(&self) -> Result<aziot_key_common::KeyHandle, Error> {
        let result = self.key_client.load_key("aziot_identityd_master_id").await;
        match result {
            Ok(key_handle) => Ok(key_handle),
            Err(_) => self
                .key_client
                .create_key_if_not_exists(
                    "aziot_identityd_master_id",
                    aziot_key_common::CreateKeyValue::Generate,
                    &[
                        aziot_key_common::KeyUsage::Derive,
                        aziot_key_common::KeyUsage::Sign,
                    ],
                )
                .await
                .map_err(|err| {
                    Error::Internal(crate::error::InternalError::MasterIdentityKey(err))
                }),
        }
    }

    async fn get_module_derived_keys(
        &self,
        master_id: aziot_key_common::KeyHandle,
        module: aziot_identity_common::hub::Module,
    ) -> Result<
        (
            aziot_key_common::KeyHandle,
            aziot_key_common::KeyHandle,
            Vec<u8>,
            Vec<u8>,
        ),
        Error,
    > {
        let mut module_derived_name = module.module_id;

        module_derived_name.push_str(&format!(
            ":{}",
            module.generation_id.ok_or(Error::ModuleNotFound)?
        ));

        let mut primary_derived_name = module_derived_name.clone();
        primary_derived_name.push_str(":primary");

        let mut secondary_derived_name = module_derived_name;
        secondary_derived_name.push_str(":secondary");

        let primary_key_handle = self
            .key_client
            .create_derived_key(&master_id, &primary_derived_name.into_bytes())
            .await
            .map_err(|err| Error::Internal(crate::error::InternalError::MasterIdentityKey(err)))?;
        let primary_key = self
            .key_client
            .export_derived_key(&primary_key_handle.clone())
            .await
            .map_err(|err| Error::Internal(crate::error::InternalError::MasterIdentityKey(err)))?;

        let secondary_key_handle = self
            .key_client
            .create_derived_key(&master_id, &secondary_derived_name.into_bytes())
            .await
            .map_err(|err| Error::Internal(crate::error::InternalError::MasterIdentityKey(err)))?;
        let secondary_key = self
            .key_client
            .export_derived_key(&secondary_key_handle.clone())
            .await
            .map_err(|err| Error::Internal(crate::error::InternalError::MasterIdentityKey(err)))?;

        Ok((
            primary_key_handle,
            secondary_key_handle,
            primary_key,
            secondary_key,
        ))
    }

    pub async fn provision_device(
        &mut self,
        provisioning: config::Provisioning,
        skip_if_backup_is_valid: bool,
    ) -> Result<aziot_identity_common::ProvisioningStatus, Error> {
        let device = match provisioning.provisioning {
            config::ProvisioningType::Manual {
                iothub_hostname,
                device_id,
                authentication,
            } => {
                let credentials = match authentication {
                    config::ManualAuthMethod::SharedPrivateKey { device_id_pk } => {
                        aziot_identity_common::Credentials::SharedPrivateKey(device_id_pk)
                    }
                    config::ManualAuthMethod::X509 {
                        identity_cert,
                        identity_pk,
                    } => {
                        self.create_identity_cert_if_not_exist_or_expired(
                            &identity_pk,
                            &identity_cert,
                            &device_id,
                        )
                        .await?;
                        aziot_identity_common::Credentials::X509 {
                            identity_cert,
                            identity_pk,
                        }
                    }
                };
                let device = aziot_identity_common::IoTHubDevice {
                    iothub_hostname,
                    device_id,
                    credentials,
                };
                self.set_device(&device);
                aziot_identity_common::ProvisioningStatus::Provisioned(device)
            }
            config::ProvisioningType::Dps {
                global_endpoint,
                scope_id,
                attestation,
            } => {
                async fn operation_to_iot_hub_device(
                    credentials: aziot_identity_common::Credentials,
                    operation: aziot_dps_client_async::model::RegistrationOperationStatus,
                ) -> Result<aziot_identity_common::IoTHubDevice, Error> {
                    let status = operation.status;
                    assert!(!status.eq_ignore_ascii_case("assigning"));

                    let mut state = operation.registration_state.ok_or(Error::DeviceNotFound)?;
                    let iothub_hostname = state.assigned_hub.get_or_insert("".into());
                    let device_id = state.device_id.get_or_insert("".into());
                    let device = aziot_identity_common::IoTHubDevice {
                        iothub_hostname: iothub_hostname.clone(),
                        device_id: device_id.clone(),
                        credentials,
                    };

                    Ok(device)
                }

                let dps_client = aziot_dps_client_async::Client::new(
                    &global_endpoint,
                    &scope_id,
                    self.key_client.clone(),
                    self.key_engine.clone(),
                    self.cert_client.clone(),
                    self.tpm_client.clone(),
                    self.proxy_uri.clone(),
                );

                let device = match attestation {
                    config::DpsAttestationMethod::SymmetricKey {
                        registration_id,
                        symmetric_key,
                    } => {
                        let dps_auth_kind = aziot_dps_client_async::DpsAuthKind::SymmetricKey {
                            sas_key: symmetric_key.clone(),
                        };
                        let credential = aziot_identity_common::Credentials::SharedPrivateKey(
                            symmetric_key.clone(),
                        );

                        let backup_device =
                            self.get_backup_provisioning_info(credential.clone())?;

                        if skip_if_backup_is_valid && backup_device.is_some() {
                            backup_device.expect("backup device cannot be none")
                        } else {
                            let operation = dps_client
                                .register(&registration_id, &dps_auth_kind)
                                .await
                                .map_err(Error::DPSClient)?;

                            operation_to_iot_hub_device(credential, operation).await?
                        }
                    }
                    config::DpsAttestationMethod::X509 {
                        registration_id,
                        identity_cert,
                        identity_pk,
                    } => {
                        self.create_identity_cert_if_not_exist_or_expired(
                            &identity_pk,
                            &identity_cert,
                            &registration_id,
                        )
                        .await?;

                        let dps_auth_kind = aziot_dps_client_async::DpsAuthKind::X509 {
                            identity_cert: identity_cert.clone(),
                            identity_pk: identity_pk.clone(),
                        };
                        let credential = aziot_identity_common::Credentials::X509 {
                            identity_cert: identity_cert.clone(),
                            identity_pk: identity_pk.clone(),
                        };

                        let backup_device =
                            self.get_backup_provisioning_info(credential.clone())?;

                        if skip_if_backup_is_valid && backup_device.is_some() {
                            backup_device.expect("backup device cannot be none")
                        } else {
                            let operation = dps_client
                                .register(&registration_id, &dps_auth_kind)
                                .await
                                .map_err(Error::DPSClient)?;

                            operation_to_iot_hub_device(credential, operation).await?
                        }
                    }
                    config::DpsAttestationMethod::Tpm { registration_id } => {
                        let dps_auth_kind = aziot_dps_client_async::DpsAuthKind::Tpm;
                        let credential = aziot_identity_common::Credentials::Tpm;

                        let backup_device =
                            self.get_backup_provisioning_info(credential.clone())?;

                        if skip_if_backup_is_valid && backup_device.is_some() {
                            backup_device.expect("backup device cannot be none")
                        } else {
                            let operation = dps_client
                                .register(&registration_id, &dps_auth_kind)
                                .await
                                .map_err(Error::DPSClient)?;

                            operation_to_iot_hub_device(credential, operation).await?
                        }
                    }
                };
                self.set_device(&device);
                aziot_identity_common::ProvisioningStatus::Provisioned(device)
            }
            config::ProvisioningType::None => {
                log::info!("Skipping provisioning with IoT Hub.");

                aziot_identity_common::ProvisioningStatus::Unprovisioned
            }
        };
        Ok(device)
    }

    fn get_backup_provisioning_info(
        &self,
        credentials: aziot_identity_common::Credentials,
    ) -> Result<Option<aziot_identity_common::IoTHubDevice>, Error> {
        let mut prev_device_info_path = self.homedir_path.clone();
        prev_device_info_path.push("device_info");

        if prev_device_info_path.exists() {
            let prev_hub_device_info =
                HubDeviceInfo::new(&prev_device_info_path).map_err(Error::Internal)?;

            match prev_hub_device_info {
                Some(device_info) => {
                    let device = aziot_identity_common::IoTHubDevice {
                        iothub_hostname: device_info.hub_name,
                        device_id: device_info.device_id,
                        credentials,
                    };

                    return Ok(Some(device));
                }
                None => return Ok(None),
            }
        }

        Ok(None)
    }

    async fn create_identity_cert_if_not_exist_or_expired(
        &self,
        identity_pk: &str,
        identity_cert: &str,
        subject: &str,
    ) -> Result<(), Error> {
        // Retrieve existing cert and check it for expiry.
        let device_id_cert = match self.cert_client.get_cert(identity_cert).await {
            Ok(pem) => {
                let cert = openssl::x509::X509::from_pem(&pem).map_err(|err| {
                    Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                })?;
                let cert_expiration = cert.as_ref().not_after();
                let current_time = openssl::asn1::Asn1Time::days_from_now(0).map_err(|err| {
                    Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                })?;
                let expiration_time = current_time.diff(cert_expiration).map_err(|err| {
                    Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                })?;

                if expiration_time.days < 1 {
                    log::info!("{} has expired. Renewing certificate", identity_cert);

                    None
                } else {
                    Some(pem)
                }
            }
            Err(_) => {
                // TODO: Need to check if key exists.
                // If this function fails, delete any key it creates but don't delete an existing key.

                None
            }
        };

        // Create new certificate if needed.
        if device_id_cert.is_none() {
            let key_handle = self
                .key_client
                .create_key_pair_if_not_exists(identity_pk, Some("rsa-2048:*"))
                .await
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
            let key_handle = std::ffi::CString::new(key_handle.0)
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;

            let mut key_engine = self.key_engine.lock().await;
            let private_key = key_engine
                .load_private_key(&key_handle)
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
            let public_key = key_engine
                .load_public_key(&key_handle)
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;

            let result = async {
                let csr = create_csr(&subject, &public_key, &private_key, None).map_err(|err| {
                    Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                })?;

                let _ = self
                    .cert_client
                    .create_cert(&identity_cert, &csr, None)
                    .await
                    .map_err(|err| {
                        Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                    })?;

                Ok::<(), Error>(())
            }
            .await;

            if let Err(err) = result {
                // TODO: need to delete key from keyd.

                return Err(err);
            }
        }

        Ok(())
    }

    pub async fn reconcile_hub_identities(&self, settings: config::Settings) -> Result<(), Error> {
        let settings = settings
            .check()
            .map_err(|err| Error::Internal(InternalError::BadSettings(err)))?;

        let settings_serialized =
            toml::to_vec(&settings).expect("serializing settings cannot fail");

        let (_, mut current_module_set, _) =
            crate::configext::prepare_authorized_principals(&settings.principal);

        match &self.iot_hub_device {
            Some(device) => {
                let mut prev_settings_path = self.homedir_path.clone();
                prev_settings_path.push("prev_state");

                let mut prev_device_info_path = self.homedir_path.clone();
                prev_device_info_path.push("device_info");

                let curr_hub_device_info = HubDeviceInfo {
                    hub_name: device.iothub_hostname.clone(),
                    device_id: device.device_id.clone(),
                };

                let device_status = toml::to_string(&curr_hub_device_info)
                    .map_err(|err| Error::Internal(InternalError::SerializeDeviceInfo(err)))?;

                // Only consider the previous Hub modules if the current and previous Hub devices match.
                let prev_module_set =
                    if prev_settings_path.exists() && prev_device_info_path.exists() {
                        let prev_hub_device_info =
                            HubDeviceInfo::new(&prev_device_info_path).map_err(Error::Internal)?;

                        if prev_hub_device_info == Some(curr_hub_device_info) {
                            let prev_settings = crate::configext::load_file(&prev_settings_path)
                                .map_err(Error::Internal)?;
                            let (_, prev_hub_modules, _) =
                                crate::configext::prepare_authorized_principals(
                                    &prev_settings.principal,
                                );
                            prev_hub_modules
                        } else {
                            std::collections::BTreeSet::default()
                        }
                    } else {
                        std::collections::BTreeSet::default()
                    };

                if prev_module_set.is_empty() && current_module_set.is_empty() {
                    return Ok(());
                }

                let hub_module_ids = self.get_module_identities().await?;

                for m in hub_module_ids {
                    if let aziot_identity_common::Identity::Aziot(m) = m {
                        if let Some(m) = m.module_id {
                            if !current_module_set.contains(&m) && prev_module_set.contains(&m) {
                                self.delete_module_identity(&m.0).await?;
                                log::info!("Hub identity {:?} removed", &m.0);
                            } else if current_module_set.contains(&m) {
                                if prev_module_set.contains(&m) {
                                    current_module_set.remove(&m);
                                    log::info!("Hub identity {:?} already exists", &m.0);
                                } else {
                                    self.delete_module_identity(&m.0).await?;
                                    log::info!("Hub identity {:?} will be recreated", &m.0);
                                }
                            }
                        } else {
                            log::warn!("invalid identity type returned by get_module_identities");
                        }
                    }
                }

                for m in current_module_set {
                    self.create_module_identity(&m.0).await?;
                    log::info!("Hub identity {:?} added", &m.0);
                }

                let () = std::fs::write(prev_device_info_path, device_status)
                    .map_err(|err| Error::Internal(InternalError::SaveDeviceInfo(err)))?;

                let () = std::fs::write(prev_settings_path, &settings_serialized)
                    .map_err(|err| Error::Internal(InternalError::SaveSettings(err)))?;
            }
            None => log::info!("reconcilation skipped since device is not provisioned"),
        }

        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq, PartialOrd, serde::Deserialize, serde::Serialize)]
pub struct HubDeviceInfo {
    pub hub_name: String,

    pub device_id: String,
}

impl HubDeviceInfo {
    pub fn new(filename: &Path) -> Result<Option<Self>, InternalError> {
        let info = std::fs::read_to_string(filename).map_err(InternalError::LoadDeviceInfo)?;

        let info = match info.as_str() {
            "unprovisioned" => None,
            _ => Some(toml::from_str(&info).map_err(InternalError::ParseDeviceInfo)?),
        };

        Ok(info)
    }

    pub fn unprovisioned() -> String {
        "unprovisioned".to_owned()
    }
}
