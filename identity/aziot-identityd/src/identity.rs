// Copyright (c) Microsoft. All rights reserved.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aziot_identityd_config as config;

use crate::create_csr;
use crate::error::{Error, InternalError};

const IOTHUB_ENCODE_SET: &percent_encoding::AsciiSet =
    &http_common::PATH_SEGMENT_ENCODE_SET.add(b'=');

const MODULE_BACKUP_LOCATION: &str = "modules";

pub(crate) const DEVICE_BACKUP_LOCATION: &str = "device_info";

pub struct IdentityManager {
    homedir_path: std::path::PathBuf,
    req_timeout: std::time::Duration,
    req_retries: u32,
    dps_trust_bundle: String,
    key_client: Arc<aziot_key_client_async::Client>,
    key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
    cert_client: Arc<aziot_cert_client_async::Client>,
    tpm_client: Arc<aziot_tpm_client_async::Client>,
    iot_hub_device: Option<aziot_identity_common::IoTHubDevice>,
    proxy_uri: Option<hyper::Uri>,
}

impl IdentityManager {
    pub fn new(
        settings: &config::Settings,
        key_client: Arc<aziot_key_client_async::Client>,
        key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
        cert_client: Arc<aziot_cert_client_async::Client>,
        tpm_client: Arc<aziot_tpm_client_async::Client>,
        iot_hub_device: Option<aziot_identity_common::IoTHubDevice>,
        proxy_uri: Option<hyper::Uri>,
    ) -> Self {
        IdentityManager {
            homedir_path: settings.homedir.clone(),
            req_timeout: std::time::Duration::from_secs(settings.cloud_timeout_sec),
            req_retries: settings.cloud_retries,
            dps_trust_bundle: settings.dps_trust_bundle.clone(),
            key_client,
            key_engine,
            cert_client,
            tpm_client,
            iot_hub_device,
            proxy_uri,
        }
    }

    pub async fn should_renew_credential(&self) -> bool {
        // Do not renew credentials that are not managed by DPS.
        if let Some(device) = &self.iot_hub_device {
            match &device.credentials {
                aziot_identity_common::Credentials::X509 {
                    identity_cert,
                    identity_pk: _,
                } => {
                    if identity_cert != aziot_identity_common::DPS_IDENTITY_CERT {
                        return false;
                    }
                }
                _ => return false,
            };
        } else {
            return false;
        };

        // Renew certificates that are invalid, expired, or close to expiry.
        match self
            .cert_client
            .get_cert(aziot_identity_common::DPS_IDENTITY_CERT)
            .await
        {
            Ok(identity_cert) => {
                let identity_cert = match openssl::x509::X509::from_pem(&identity_cert) {
                    Ok(identity_cert) => identity_cert,
                    Err(_) => return true,
                };

                let now = openssl::asn1::Asn1Time::days_from_now(0)
                    .expect("current time should be valid");

                let diff = match now.diff(identity_cert.not_after()) {
                    Ok(diff) => diff,
                    Err(_) => return true,
                };

                diff.days < 1
            }
            Err(_) => true,
        }
    }

    pub fn set_device(&mut self, device: &aziot_identity_common::IoTHubDevice) {
        ModuleBackup::set_device(
            &self.homedir_path,
            &device.iothub_hostname,
            &device.device_id,
        );
        self.iot_hub_device = Some(device.clone());
    }

    pub fn clear_device(&mut self) {
        // Clear the backed up device state before reprovisioning.
        // If this fails, log a warning but continue with reprovisioning.
        let mut backup_file = self.homedir_path.clone();
        backup_file.push(DEVICE_BACKUP_LOCATION);

        if let Err(err) = std::fs::remove_file(backup_file) {
            if err.kind() != std::io::ErrorKind::NotFound {
                log::warn!(
                    "Failed to clear device state before reprovisioning: {}",
                    err
                );
            }
        }

        // Purge all module identities for this device. These might no longer be valid after reprovision.
        if let Some(device) = &self.iot_hub_device {
            let module_backup_path = ModuleBackup::get_device_path(
                &self.homedir_path,
                &device.iothub_hostname,
                &device.device_id,
            )
            .expect("module path for existing device must be valid");

            if let Err(err) = std::fs::remove_dir_all(module_backup_path) {
                if err.kind() != std::io::ErrorKind::NotFound {
                    log::warn!(
                        "Failed to clear module identities before reprovisioning: {}",
                        err
                    );
                }
            }
        }

        self.iot_hub_device = None;
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
                    self.req_timeout,
                    self.req_retries,
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

                ModuleBackup::set_module_backup(
                    &self.homedir_path,
                    &device.iothub_hostname,
                    &device.device_id,
                    &response.module_id,
                    Some(aziot_identity_common::hub::Module {
                        module_id: response.module_id.clone(),
                        device_id: response.device_id.clone(),
                        generation_id: response.generation_id.clone(),
                        managed_by: response.managed_by.clone(),
                        authentication: None,
                    }),
                );

                let identity =
                    aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
                        hub_name: device.iothub_hostname.clone(),
                        gateway_host: device.local_gateway_hostname.clone(),
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
                    self.req_timeout,
                    self.req_retries,
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

                ModuleBackup::set_module_backup(
                    &self.homedir_path,
                    &device.iothub_hostname,
                    &device.device_id,
                    &response.module_id,
                    Some(aziot_identity_common::hub::Module {
                        module_id: response.module_id.clone(),
                        device_id: response.device_id.clone(),
                        generation_id: response.generation_id.clone(),
                        managed_by: response.managed_by.clone(),
                        authentication: None,
                    }),
                );

                let identity =
                    aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
                        hub_name: device.iothub_hostname.clone(),
                        gateway_host: device.local_gateway_hostname.clone(),
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
                    gateway_host: device.local_gateway_hostname.clone(),
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
                    self.req_timeout,
                    self.req_retries,
                    self.key_client.clone(),
                    self.key_engine.clone(),
                    self.cert_client.clone(),
                    self.tpm_client.clone(),
                    self.proxy_uri.clone(),
                );
                let module = {
                    let result = client.get_module(&*module_id).await;

                    match result {
                        Ok(module) => {
                            ModuleBackup::set_module_backup(
                                &self.homedir_path,
                                &device.iothub_hostname,
                                &device.device_id,
                                &module.module_id,
                                Some(aziot_identity_common::hub::Module {
                                    module_id: module.module_id.clone(),
                                    device_id: module.device_id.clone(),
                                    generation_id: module.generation_id.clone(),
                                    managed_by: module.managed_by.clone(),
                                    authentication: None,
                                }),
                            );

                            module
                        }
                        Err(err) => {
                            if err.kind() == std::io::ErrorKind::NotFound {
                                ModuleBackup::set_module_backup(
                                    &self.homedir_path,
                                    &device.iothub_hostname,
                                    &device.device_id,
                                    module_id,
                                    None,
                                );
                                return Err(Error::HubClient(err));
                            }

                            let module = ModuleBackup::get_module_backup(
                                &self.homedir_path,
                                &device.iothub_hostname,
                                &device.device_id,
                                module_id,
                            );

                            match module {
                                Some(module) => module,
                                None => return Err(Error::HubClient(err)),
                            }
                        }
                    }
                };

                let master_id_key_handle = self.get_master_identity_key().await?;
                let (primary_key_handle, _, _, _) = self
                    .get_module_derived_keys(master_id_key_handle, module.clone())
                    .await?;
                let module_credentials =
                    aziot_identity_common::Credentials::SharedPrivateKey(primary_key_handle.0);

                let identity =
                    aziot_identity_common::Identity::Aziot(aziot_identity_common::AzureIoTSpec {
                        hub_name: device.iothub_hostname.clone(),
                        gateway_host: device.local_gateway_hostname.clone(),
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
                    self.req_timeout,
                    self.req_retries,
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
                        ModuleBackup::set_module_backup(
                            &self.homedir_path,
                            &device.iothub_hostname,
                            &device.device_id,
                            &module.module_id,
                            Some(aziot_identity_common::hub::Module {
                                module_id: module.module_id.clone(),
                                device_id: module.device_id.clone(),
                                generation_id: module.generation_id.clone(),
                                managed_by: module.managed_by.clone(),
                                authentication: None,
                            }),
                        );

                        aziot_identity_common::Identity::Aziot(
                            aziot_identity_common::AzureIoTSpec {
                                hub_name: device.iothub_hostname.clone(),
                                gateway_host: device.local_gateway_hostname.clone(),
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
                    self.req_timeout,
                    self.req_retries,
                    self.key_client.clone(),
                    self.key_engine.clone(),
                    self.cert_client.clone(),
                    self.tpm_client.clone(),
                    self.proxy_uri.clone(),
                );
                let () = client
                    .delete_module(&*module_id)
                    .await
                    .map_err(Error::HubClient)?;

                ModuleBackup::set_module_backup(
                    &self.homedir_path,
                    &device.iothub_hostname,
                    &device.device_id,
                    module_id,
                    None,
                );

                Ok(())
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
                // Remove any DPS-issued credentials, which won't be valid after changing to manual provisioning.
                self.delete_credential(&self.dps_trust_bundle, None).await;
                self.delete_credential(
                    aziot_identity_common::DPS_IDENTITY_CERT,
                    Some(aziot_identity_common::DPS_IDENTITY_CERT_KEY),
                )
                .await;

                let credentials = match authentication {
                    config::ManualAuthMethod::SharedPrivateKey { device_id_pk } => {
                        aziot_identity_common::Credentials::SharedPrivateKey(device_id_pk)
                    }
                    config::ManualAuthMethod::X509 {
                        identity_cert,
                        identity_pk,
                    } => {
                        // IoT Hub doesn't require device ID to match identity certificate CN
                        let _ = self
                            .create_identity_cert_if_not_exist_or_expired(
                                &identity_pk,
                                &identity_cert,
                                Some(&device_id),
                            )
                            .await?;
                        aziot_identity_common::Credentials::X509 {
                            identity_cert,
                            identity_pk,
                        }
                    }
                };
                let device = aziot_identity_common::IoTHubDevice {
                    local_gateway_hostname: provisioning
                        .local_gateway_hostname
                        .clone()
                        .unwrap_or_else(|| iothub_hostname.clone()),
                    iothub_hostname,
                    device_id,
                    credentials,
                };
                self.set_device(&device);

                log::info!("Updated device info for {}.", device.device_id);
                aziot_identity_common::ProvisioningStatus::Provisioned(device)
            }
            config::ProvisioningType::Dps {
                global_endpoint,
                scope_id,
                attestation,
            } => {
                if provisioning.local_gateway_hostname.is_some() {
                    return Err(Error::DpsNotSupportedInNestedMode);
                }

                let dps_client = aziot_dps_client_async::Client::new(
                    &global_endpoint,
                    &scope_id,
                    self.req_timeout,
                    self.req_retries,
                    self.key_client.clone(),
                    self.key_engine.clone(),
                    self.cert_client.clone(),
                    self.tpm_client.clone(),
                    self.proxy_uri.clone(),
                    aziot_identity_common::DPS_IDENTITY_CERT_KEY.to_string(),
                );

                let (dps_auth_kind, registration_id, credentials) = match attestation {
                    config::DpsAttestationMethod::SymmetricKey {
                        registration_id,
                        symmetric_key,
                    } => {
                        let dps_auth_kind = aziot_dps_client_async::DpsAuthKind::SymmetricKey {
                            sas_key: symmetric_key.clone(),
                        };
                        let credentials =
                            aziot_identity_common::Credentials::SharedPrivateKey(symmetric_key);

                        (dps_auth_kind, registration_id, credentials)
                    }
                    config::DpsAttestationMethod::X509 {
                        registration_id,
                        identity_cert,
                        identity_pk,
                    } => {
                        // DPS requires registration ID to match identity certificate CN
                        let cert_subject_name = self
                            .create_identity_cert_if_not_exist_or_expired(
                                &identity_pk,
                                &identity_cert,
                                registration_id.as_ref(),
                            )
                            .await?;

                        let registration_id = match registration_id {
                            Some(registration_id) => registration_id,
                            None => cert_subject_name.map_err(|err| {
                                Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                            })?,
                        };

                        let dps_auth_kind = aziot_dps_client_async::DpsAuthKind::X509 {
                            identity_cert: identity_cert.clone(),
                            identity_pk: identity_pk.clone(),
                        };
                        let credentials = aziot_identity_common::Credentials::X509 {
                            identity_cert: identity_cert.clone(),
                            identity_pk: identity_pk.clone(),
                        };

                        (dps_auth_kind, registration_id, credentials)
                    }
                    config::DpsAttestationMethod::Tpm { registration_id } => {
                        let dps_auth_kind = aziot_dps_client_async::DpsAuthKind::Tpm;
                        let credentials = aziot_identity_common::Credentials::Tpm;

                        (dps_auth_kind, registration_id, credentials)
                    }
                };

                let device = self
                    .dps_provision(
                        skip_if_backup_is_valid,
                        dps_client,
                        dps_auth_kind,
                        registration_id,
                        credentials,
                        provisioning.local_gateway_hostname,
                    )
                    .await?;

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

    async fn dps_provision(
        &self,
        skip_if_backup_is_valid: bool,
        dps_client: aziot_dps_client_async::Client,
        dps_auth_kind: aziot_dps_client_async::DpsAuthKind,
        registration_id: String,
        credentials: aziot_identity_common::Credentials,
        local_gateway_hostname: Option<String>,
    ) -> Result<aziot_identity_common::IoTHubDevice, Error> {
        let backup_device = self
            .get_backup_provisioning_info(credentials.clone())
            .await?;

        if skip_if_backup_is_valid && backup_device.is_some() {
            let backup_device = backup_device.expect("backup device cannot be none");
            log::info!("Provisioned with backup for {}.", backup_device.device_id);

            return Ok(backup_device);
        }

        let operation = dps_client
            .register(&registration_id, &dps_auth_kind)
            .await
            .map_err(Error::DpsClient)?;

        // DPS client registration won't return if the status is "assigning".
        assert!(!operation.status.eq_ignore_ascii_case("assigning"));

        let state = operation.registration_state.ok_or(Error::DeviceNotFound)?;

        let (iothub_hostname, device_id) = match (state.assigned_hub, state.device_id) {
            (Some(iothub_hostname), Some(device_id)) => (iothub_hostname, device_id),
            _ => {
                return Err(Error::DpsClient(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    state.error_message.unwrap_or_default(),
                )))
            }
        };

        log::info!("Successfully provisioned with DPS.");

        if let Some(trust_bundle) = state.trust_bundle {
            self.save_dps_trust_bundle(trust_bundle).await?;
        } else {
            // New provisioning info does not use a DPS-issued trust bundle.
            // Delete any trust bundle left by any previously provisioned device,
            // as that won't be valid anymore.
            self.delete_credential(&self.dps_trust_bundle, None).await;
        }

        let credentials = if let Some(identity_cert) = state.identity_cert {
            self.save_dps_identity_cert(identity_cert).await?;

            aziot_identity_common::Credentials::X509 {
                identity_cert: aziot_identity_common::DPS_IDENTITY_CERT.to_string(),
                identity_pk: aziot_identity_common::DPS_IDENTITY_CERT_KEY.to_string(),
            }
        } else {
            // New provisioning info does not use a DPS-issued identity certificate.
            // Delete any identity certificate left by any previously provisioned device,
            // as that won't be valid anymore.
            self.delete_credential(
                aziot_identity_common::DPS_IDENTITY_CERT,
                Some(aziot_identity_common::DPS_IDENTITY_CERT_KEY),
            )
            .await;

            credentials
        };

        Ok(aziot_identity_common::IoTHubDevice {
            local_gateway_hostname: local_gateway_hostname
                .unwrap_or_else(|| iothub_hostname.clone()),
            iothub_hostname,
            device_id,
            credentials,
        })
    }

    async fn save_dps_trust_bundle(
        &self,
        trust_bundle: aziot_dps_client_async::model::TrustBundle,
    ) -> Result<(), Error> {
        let mut certificates = String::new();

        for cert in trust_bundle.certificates {
            certificates.push_str(&cert.certificate);

            let last = certificates.chars().last().ok_or_else(|| {
                Error::Internal(InternalError::CreateCertificate(Box::new(
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "empty DPS trust bundle"),
                )))
            })?;

            if last != '\n' {
                certificates.push('\n');
            }
        }

        self.cert_client
            .import_cert(&self.dps_trust_bundle, certificates.as_bytes())
            .await
            .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;

        log::info!(
            "Saved DPS-issued trust bundle as {}.",
            &self.dps_trust_bundle
        );

        Ok(())
    }

    async fn save_dps_identity_cert(&self, identity_cert: String) -> Result<(), Error> {
        let identity_cert = base64::decode(identity_cert)
            .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
        let identity_cert = openssl::x509::X509::from_der(&identity_cert)
            .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;

        let identity_cert = identity_cert
            .to_pem()
            .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;

        self.cert_client
            .import_cert(aziot_identity_common::DPS_IDENTITY_CERT, &identity_cert)
            .await
            .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;

        log::info!(
            "Saved DPS-issued identity certificate as {}.",
            aziot_identity_common::DPS_IDENTITY_CERT
        );

        Ok(())
    }

    async fn delete_credential(&self, cert: &str, key: Option<&str>) {
        // Check that the credential exists before attempting to delete to avoid
        // polluting logs with "Failed to remove..." messages.
        if self.cert_client.get_cert(cert).await.is_ok() {
            if let Err(err) = self.cert_client.delete_cert(cert).await {
                log::warn!("Failed to remove {}: {}", cert, err);
            } else {
                log::info!("Removed {}.", cert);
            }

            if let Some(key_id) = key {
                if let Ok(key_handle) = self.key_client.load_key_pair(key_id).await {
                    if let Err(err) = self.key_client.delete_key_pair(&key_handle).await {
                        log::warn!("Failed to remove key {}: {}.", key_id, err);
                    } else {
                        log::info!("Removed key {}.", key_id);
                    }
                } else {
                    log::warn!("Failed to load key {}.", key_id);
                }
            }
        }
    }

    async fn get_backup_provisioning_info(
        &self,
        credentials: aziot_identity_common::Credentials,
    ) -> Result<Option<aziot_identity_common::IoTHubDevice>, Error> {
        let mut prev_device_info_path = self.homedir_path.clone();
        prev_device_info_path.push(DEVICE_BACKUP_LOCATION);

        if prev_device_info_path.exists() {
            let prev_hub_device_info =
                HubDeviceInfo::new(&prev_device_info_path).map_err(Error::Internal)?;

            match prev_hub_device_info {
                Some(device_info) => {
                    // This function is only called for DPS-provisioned devices. Check if DPS-issued
                    // credentials exist and prefer use of DPS-issued credentials.
                    let (cert, key) = futures_util::join!(
                        self.cert_client
                            .get_cert(aziot_identity_common::DPS_IDENTITY_CERT),
                        self.key_client
                            .load_key_pair(aziot_identity_common::DPS_IDENTITY_CERT_KEY)
                    );

                    let credentials = match (cert, key) {
                        (Ok(_), Ok(_)) => aziot_identity_common::Credentials::X509 {
                            identity_cert: aziot_identity_common::DPS_IDENTITY_CERT.to_string(),
                            identity_pk: aziot_identity_common::DPS_IDENTITY_CERT_KEY.to_string(),
                        },
                        _ => credentials,
                    };

                    let device = aziot_identity_common::IoTHubDevice {
                        local_gateway_hostname: device_info.local_gateway_hostname,
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
        subject: Option<&String>,
    ) -> Result<Result<String, Error>, Error> {
        // Retrieve existing cert and check it for expiry.
        let (device_id_cert, old_cert_subject_name) = match self
            .cert_client
            .get_cert(identity_cert)
            .await
        {
            Ok(pem) => {
                let cert = openssl::x509::X509::from_pem(&pem).map_err(|err| {
                    Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                })?;
                let cert_expiration = cert.as_ref().not_after();
                let cert_subject = cert.as_ref().subject_name();
                let cert_subject = cert_subject.entries_by_nid(openssl::nid::Nid::COMMONNAME).next()
                  .map_or(Err(Error::Internal(InternalError::CreateCertificate("old device identity certificate does not contain common name field required for registration".to_string().into()))), |common_name_entry| {
                    String::from_utf8(common_name_entry.data().as_slice().into()).map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))
                });
                let current_time = openssl::asn1::Asn1Time::days_from_now(0).map_err(|err| {
                    Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                })?;
                let expiration_time = current_time.diff(cert_expiration).map_err(|err| {
                    Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                })?;

                if expiration_time.days < 1 {
                    log::info!("{} has expired. Renewing certificate", identity_cert);

                    (None, cert_subject)
                } else {
                    (Some(pem), cert_subject)
                }
            }
            Err(_) => {
                (None, Err(Error::Internal(InternalError::CreateCertificate("old device identity certificate, which should contain the common name field required for registration, could not be retrieved".to_string().into()))))
            }
        };

        // Create new certificate if needed.
        if device_id_cert.is_none() {
            if let Ok(key_handle) = self.key_client.load_key_pair(identity_pk).await {
                self.key_client
                    .delete_key_pair(&key_handle)
                    .await
                    .map_err(|err| {
                        Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                    })?;
            }
            let new_cert_subject = match subject {
                Some(subject) => subject.to_string(),
                None => old_cert_subject_name.map_err(|err| {
                    Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                })?,
            };

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

            let csr = create_csr(new_cert_subject.as_str(), &public_key, &private_key, None)
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;

            let new_cert_pem = self
                .cert_client
                .create_cert(identity_cert, &csr, None)
                .await
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;

            let cert = openssl::x509::X509::from_pem(&new_cert_pem)
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
            let cert_subject = cert.as_ref().subject_name();
            let cert_subject = cert_subject.entries_by_nid(openssl::nid::Nid::COMMONNAME).next()
                .map_or(Err(Error::Internal(InternalError::CreateCertificate("new device identity certificate does not contain common name field required for registration".to_string().into()))), |common_name_entry| {
                    String::from_utf8(common_name_entry.data().as_slice().into()).map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))
            });

            Ok(cert_subject)
        } else {
            Ok(old_cert_subject_name)
        }
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
                // Encapsulate the device_info update along with "module_info" for offline store
                // Make sure module_info is wiped when device_info is wiped

                let mut prev_settings_path = self.homedir_path.clone();
                prev_settings_path.push("prev_state");

                let mut prev_device_info_path = self.homedir_path.clone();
                prev_device_info_path.push(DEVICE_BACKUP_LOCATION);

                let curr_hub_device_info = HubDeviceInfo {
                    hub_name: device.iothub_hostname.clone(),
                    local_gateway_hostname: device.local_gateway_hostname.clone(),
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

                // Write out device state and settings.
                // This overwrites any existing device state and settings backup.
                std::fs::write(prev_device_info_path, device_status)
                    .map_err(|err| Error::Internal(InternalError::SaveDeviceInfo(err)))?;

                std::fs::write(prev_settings_path, &settings_serialized)
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

    pub local_gateway_hostname: String,

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

pub struct ModuleBackup {}

impl ModuleBackup {
    pub fn set_device(homedir_path: &Path, iothub_hostname: &str, device_id: &str) {
        let result = Self::get_device_path(homedir_path, iothub_hostname, device_id)
            .map_err(|err| Error::Internal(InternalError::GetModulePath(err)))
            .and_then(|path| {
                if !path.exists() {
                    // Clean old device module backups
                    let mut old_modules_path = homedir_path.to_owned();
                    old_modules_path.push(MODULE_BACKUP_LOCATION);

                    // Best effort to remove old modules backup folder, in case permissions have been set
                    // explictly on filesystem to prevent removal
                    if let Err(err) = std::fs::remove_dir_all(old_modules_path) {
                        if err.kind() != std::io::ErrorKind::NotFound {
                            log::warn!("Failed to clear old module backup state: {}", err);
                        }
                    }

                    // Create new device's module backup folder
                    return std::fs::create_dir_all(&path)
                        .map_err(|err| Error::Internal(InternalError::SaveModuleBackup(err)));
                }

                Ok(())
            });

        // Logging a warning is sufficient for per-module backup to keep the service operational for online operations
        if let Err(err) = result {
            log::warn!(
                "Failed to create module information backup state folder: {}",
                err
            );
        }
    }

    pub fn set_module_backup(
        homedir_path: &Path,
        iothub_hostname: &str,
        device_id: &str,
        module_id: &str,
        data: Option<aziot_identity_common::hub::Module>,
    ) {
        let result = match data {
            Some(module) => {
                let s = serde_json::to_string(&module).expect("serializing module cannot fail");
                Self::get_module_path(homedir_path, iothub_hostname, device_id, module_id)
                    .map_err(|err| Error::Internal(InternalError::GetModulePath(err)))
                    .and_then(|path| {
                        std::fs::write(path, s)
                            .map_err(|err| Error::Internal(InternalError::SaveModuleBackup(err)))
                    })
            }
            None => Self::get_module_path(homedir_path, iothub_hostname, device_id, module_id)
                .map_err(|err| Error::Internal(InternalError::GetModulePath(err)))
                .and_then(|path| match std::fs::remove_file(path) {
                    Ok(()) => Ok(()),
                    Err(ref err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(err) => Err(Error::Internal(InternalError::SaveModuleBackup(err))),
                }),
        };

        // Logging a warning is sufficient for per-module backup to keep the service operational for online operations
        if let Err(err) = result {
            log::warn!("Failed to save module information backup state: {}", err);
        }
    }

    pub fn get_module_backup(
        homedir_path: &Path,
        iothub_hostname: &str,
        device_id: &str,
        module_id: &str,
    ) -> Option<aziot_identity_common::hub::Module> {
        match Self::get_module_path(homedir_path, iothub_hostname, device_id, module_id) {
            Ok(path) => match std::fs::read(path) {
                Ok(module) => match serde_json::from_slice(&module) {
                    Ok(s) => Some(s),
                    Err(err) => {
                        log::error!("Invalid input from backup file. Failure reason: {}", err);
                        None
                    }
                },
                Err(ref err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    log::warn!("Could not read module backup file. Failure reason: {}", err);
                    None
                }
            },
            Err(err) => {
                log::warn!(
                    "Could not get module backup file path. Failure reason: {}",
                    err
                );
                None
            }
        }
    }

    fn get_device_path(
        homedir_path: &Path,
        iothub_hostname: &str,
        device_id: &str,
    ) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
        let mut path = homedir_path.to_owned();
        path.push(MODULE_BACKUP_LOCATION);

        let iothub_hostname_hash = openssl::hash::hash(
            openssl::hash::MessageDigest::sha256(),
            iothub_hostname.as_bytes(),
        )?;
        let iothub_hostname_hash = hex::encode(iothub_hostname_hash);

        let device_id_hash =
            openssl::hash::hash(openssl::hash::MessageDigest::sha256(), device_id.as_bytes())?;
        let device_id_hash = hex::encode(device_id_hash);

        path.push(format!("{}-{}", iothub_hostname_hash, device_id_hash));

        Ok(path)
    }

    fn get_module_path(
        homedir_path: &Path,
        iothub_hostname: &str,
        device_id: &str,
        module_id: &str,
    ) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
        let mut path = Self::get_device_path(homedir_path, iothub_hostname, device_id)?;

        let module_id_sanitized: String = module_id
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .collect();

        let module_id_hash =
            openssl::hash::hash(openssl::hash::MessageDigest::sha256(), module_id.as_bytes())?;
        let module_id_hash = hex::encode(module_id_hash);

        path.push(format!("{}-{}", module_id_sanitized, module_id_hash));

        Ok(path)
    }
}
