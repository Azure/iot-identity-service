// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_and_return,
    clippy::let_unit_value,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::type_complexity
)]
#![allow(dead_code)]

pub mod auth;
pub mod error;
mod http;
pub mod identity;
pub mod settings;

pub use error::{Error, InternalError};

/// This is the interval at which to poll DPS for registration assignment status
const DPS_ASSIGNMENT_RETRY_INTERVAL_SECS: u64 = 10;

/// This is the number of seconds to wait for DPS to complete assignment to a hub
const DPS_ASSIGNMENT_TIMEOUT_SECS: u64 = 120;

/// Private key types when creating a new identity certificate.
#[derive(Clone)]
enum KeyType {
    /// Key handle managed by keyd.
    Handle(String),

    /// Raw private key stored in memory. These keys are not persisted across runs of identityd.
    Raw,
}

pub async fn main(
    settings: settings::Settings,
) -> Result<(http_common::Connector, http::Service), Box<dyn std::error::Error>> {
    // Written to prev_settings_path if provisioning is successful.
    let settings_serialized = toml::to_vec(&settings).expect("serializing settings cannot fail");

    let homedir_path = &settings.homedir;
    let connector = settings.endpoints.aziot_identityd.clone();

    let mut prev_settings_path = homedir_path.clone();
    prev_settings_path.push("prev_state");

    let mut prev_device_info_path = homedir_path.clone();
    prev_device_info_path.push("device_info");

    if !homedir_path.exists() {
        let () =
            std::fs::create_dir_all(&homedir_path).map_err(error::InternalError::CreateHomeDir)?;
    }

    let (_pmap, hub_mset, local_mmap) = convert_to_map(&settings.principal);

    let authenticator = Box::new(|_| Ok(auth::AuthId::Unknown));

    // TODO: Enable SettingsAuthorizer once Unix Domain Sockets is ported over.
    // let authorizer = SettingsAuthorizer { pmap };
    // let authorizer = Box::new(authorizer);
    let authorizer = Box::new(|_| Ok(true));

    let api = Api::new(settings, local_mmap, authenticator, authorizer)?;
    let api = std::sync::Arc::new(futures_util::lock::Mutex::new(api));

    {
        let mut api_ = api.lock().await;

        log::info!("Provisioning starting.");
        let provisioning = api_.provision_device().await?;
        log::info!("Provisioning complete.");

        let device_status = if let aziot_identity_common::ProvisioningStatus::Provisioned(device) =
            provisioning
        {
            let curr_hub_device_info = settings::HubDeviceInfo {
                hub_name: device.iothub_hostname,
                device_id: device.device_id,
            };
            let device_status = toml::to_string(&curr_hub_device_info)?;

            // Only consider the previous Hub modules if the current and previous Hub devices match.
            let prev_hub_mset = if prev_settings_path.exists() && prev_device_info_path.exists() {
                let prev_hub_device_info = settings::HubDeviceInfo::new(&prev_device_info_path)?;

                if prev_hub_device_info == Some(curr_hub_device_info) {
                    let prev_settings = settings::Settings::new(&prev_settings_path)?;
                    let (_, prev_hub_mset, _) = convert_to_map(&prev_settings.principal);
                    prev_hub_mset
                } else {
                    std::collections::BTreeSet::default()
                }
            } else {
                std::collections::BTreeSet::default()
            };

            let () = api_.init_hub_identities(prev_hub_mset, hub_mset).await?;
            log::info!("Identity reconciliation with IoT Hub complete.");

            device_status
        } else {
            settings::HubDeviceInfo::unprovisioned()
        };

        std::fs::write(prev_device_info_path, device_status)
            .map_err(error::InternalError::SaveDeviceInfo)?;
        let () = std::fs::write(prev_settings_path, &settings_serialized)
            .map_err(error::InternalError::SaveSettings)?;
    }

    let service = http::Service { api };

    Ok((connector, service))
}

pub struct Api {
    pub settings: settings::Settings,
    pub authenticator: Box<dyn auth::authentication::Authenticator<Error = Error> + Send + Sync>,
    pub authorizer: Box<dyn auth::authorization::Authorizer<Error = Error> + Send + Sync>,
    pub id_manager: identity::IdentityManager,
    pub local_identities:
        std::collections::BTreeMap<aziot_identity_common::ModuleId, Option<settings::LocalIdOpts>>,

    key_client: std::sync::Arc<aziot_key_client_async::Client>,
    key_engine: std::sync::Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
    cert_client: std::sync::Arc<aziot_cert_client_async::Client>,
}

impl Api {
    pub fn new(
        settings: settings::Settings,
        local_identities: std::collections::BTreeMap<
            aziot_identity_common::ModuleId,
            Option<settings::LocalIdOpts>,
        >,
        authenticator: Box<dyn auth::authentication::Authenticator<Error = Error> + Send + Sync>,
        authorizer: Box<dyn auth::authorization::Authorizer<Error = Error> + Send + Sync>,
    ) -> Result<Self, Error> {
        let key_service_connector = settings.endpoints.aziot_keyd.clone();

        let key_client = {
            let key_client = aziot_key_client_async::Client::new(
                aziot_key_common_http::ApiVersion::V2020_09_01,
                key_service_connector.clone(),
            );
            let key_client = std::sync::Arc::new(key_client);
            key_client
        };

        let key_engine = {
            let key_client = aziot_key_client::Client::new(
                aziot_key_common_http::ApiVersion::V2020_09_01,
                key_service_connector,
            );
            let key_client = std::sync::Arc::new(key_client);
            let key_engine = aziot_key_openssl_engine::load(key_client)
                .map_err(|err| Error::Internal(InternalError::LoadKeyOpensslEngine(err)))?;
            let key_engine = std::sync::Arc::new(futures_util::lock::Mutex::new(key_engine));
            key_engine
        };

        let cert_client = {
            let cert_service_connector = settings.endpoints.aziot_certd.clone();
            let cert_client = aziot_cert_client_async::Client::new(
                aziot_cert_common_http::ApiVersion::V2020_09_01,
                cert_service_connector,
            );
            let cert_client = std::sync::Arc::new(cert_client);
            cert_client
        };

        let id_manager = identity::IdentityManager::new(
            key_client.clone(),
            key_engine.clone(),
            cert_client.clone(),
            None,
        );

        Ok(Api {
            settings,
            authenticator,
            authorizer,
            id_manager,
            local_identities,

            key_client,
            key_engine,
            cert_client,
        })
    }

    pub async fn get_caller_identity(
        &self,
        auth_id: auth::AuthId,
    ) -> Result<aziot_identity_common::Identity, Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::GetDevice,
        })? {
            return Err(Error::Authorization);
        }

        self.id_manager.get_device_identity().await
    }

    pub async fn get_identity(
        &self,
        auth_id: auth::AuthId,
        id_type: Option<String>,
        module_id: &str,
    ) -> Result<aziot_identity_common::Identity, Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::GetModule(String::from(module_id)),
        })? {
            return Err(Error::Authorization);
        }

        // If id_type is not provided, return module identity.
        let id_type = id_type.unwrap_or_else(|| "aziot".to_owned());

        match id_type.as_str() {
            "aziot" => self.id_manager.get_module_identity(module_id).await,
            "local" => self.issue_local_identity(module_id).await,
            _ => Err(Error::invalid_parameter("id_type", "invalid id_type")),
        }
    }

    pub async fn get_identities(
        &self,
        auth_id: auth::AuthId,
        id_type: &str,
    ) -> Result<Vec<aziot_identity_common::Identity>, Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::GetAllHubModules,
        })? {
            return Err(Error::Authorization);
        }

        if id_type.eq("aziot") {
            self.id_manager.get_module_identities().await
        } else {
            Err(Error::invalid_parameter("id_type", "invalid id_type"))
        }
    }

    pub async fn get_device_identity(
        &self,
        auth_id: auth::AuthId,
        _idtype: &str,
    ) -> Result<aziot_identity_common::Identity, Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::GetDevice,
        })? {
            return Err(Error::Authorization);
        }

        self.id_manager.get_device_identity().await
    }

    pub async fn create_identity(
        &self,
        auth_id: auth::AuthId,
        _idtype: &str,
        module_id: &str,
    ) -> Result<aziot_identity_common::Identity, Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::CreateModule(String::from(module_id)),
        })? {
            return Err(Error::Authorization);
        }

        //TODO: match identity type based on uid configuration and create and get identity from appropriate identity manager (Hub or local)
        self.id_manager.create_module_identity(module_id).await
    }

    pub async fn update_identity(
        &self,
        auth_id: auth::AuthId,
        _idtype: &str,
        module_id: &str,
    ) -> Result<aziot_identity_common::Identity, Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::UpdateModule(String::from(module_id)),
        })? {
            return Err(Error::Authorization);
        }

        //TODO: match identity type based on uid configuration and create and get identity from appropriate identity manager (Hub or local)
        self.id_manager.update_module_identity(module_id).await
    }

    pub async fn delete_identity(
        &self,
        auth_id: auth::AuthId,
        _idtype: &str,
        module_id: &str,
    ) -> Result<(), Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::DeleteModule(String::from(module_id)),
        })? {
            return Err(Error::Authorization);
        }

        //TODO: match identity type based on uid configuration and create and get identity from appropriate identity manager (Hub or local)
        self.id_manager.delete_module_identity(module_id).await
    }

    pub async fn get_trust_bundle(
        &self,
        auth_id: auth::AuthId,
    ) -> Result<aziot_cert_common_http::Pem, Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::GetTrustBundle,
        })? {
            return Err(Error::Authorization);
        }

        //TODO: invoke get trust bundle
        Ok(aziot_cert_common_http::Pem {
            0: std::vec::Vec::default(),
        })
    }

    pub async fn reprovision_device(&mut self, auth_id: auth::AuthId) -> Result<(), Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::ReprovisionDevice,
        })? {
            return Err(Error::Authorization);
        }

        let _ = self.provision_device().await?;
        Ok(())
    }

    pub async fn init_hub_identities(
        &self,
        prev_module_set: std::collections::BTreeSet<aziot_identity_common::ModuleId>,
        mut current_module_set: std::collections::BTreeSet<aziot_identity_common::ModuleId>,
    ) -> Result<(), Error> {
        if prev_module_set.is_empty() && current_module_set.is_empty() {
            return Ok(());
        }

        let hub_module_ids = self.id_manager.get_module_identities().await?;

        for m in hub_module_ids {
            if let aziot_identity_common::Identity::Aziot(m) = m {
                if let Some(m) = m.module_id {
                    if !current_module_set.contains(&m) && prev_module_set.contains(&m) {
                        self.id_manager.delete_module_identity(&m.0).await?;
                        log::info!("Hub identity {:?} removed", &m.0);
                    } else if current_module_set.contains(&m) {
                        current_module_set.remove(&m);
                        log::info!("Hub identity {:?} already exists", &m.0);
                    }
                } else {
                    log::warn!("invalid identity type returned by get_module_identities");
                }
            }
        }

        for m in current_module_set {
            self.id_manager.create_module_identity(&m.0).await?;
            log::info!("Hub identity {:?} added", &m.0);
        }

        Ok(())
    }

    pub async fn provision_device(
        &mut self,
    ) -> Result<aziot_identity_common::ProvisioningStatus, Error> {
        let device = match self.settings.clone().provisioning.provisioning {
            settings::ProvisioningType::Manual {
                iothub_hostname,
                device_id,
                authentication,
            } => {
                let credentials = match authentication {
                    settings::ManualAuthMethod::SharedPrivateKey { device_id_pk } => {
                        aziot_identity_common::Credentials::SharedPrivateKey(device_id_pk)
                    }
                    settings::ManualAuthMethod::X509 {
                        identity_cert,
                        identity_pk,
                    } => {
                        self.create_identity_cert_if_not_exist_or_expired(
                            KeyType::Handle(identity_pk.clone()),
                            &identity_cert,
                            &device_id,
                            None,
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
                self.id_manager.set_device(&device);
                aziot_identity_common::ProvisioningStatus::Provisioned(device)
            }
            settings::ProvisioningType::Dps {
                global_endpoint,
                scope_id,
                attestation,
            } => {
                let device = match attestation {
                    settings::DpsAttestationMethod::SymmetricKey {
                        registration_id,
                        symmetric_key,
                    } => {
                        let result = {
                            let mut key_engine = self.key_engine.lock().await;
                            aziot_dps_client_async::register(
                                global_endpoint.as_str(),
                                &scope_id,
                                &registration_id,
                                Some(symmetric_key.clone()),
                                None,
                                None,
                                &self.key_client,
                                &mut *key_engine,
                                &self.cert_client,
                            )
                            .await
                        };
                        let device = match result {
                            Ok(operation) => {
                                let mut retry_count = (DPS_ASSIGNMENT_TIMEOUT_SECS
                                    / DPS_ASSIGNMENT_RETRY_INTERVAL_SECS)
                                    + 1;
                                let credential =
                                    aziot_identity_common::Credentials::SharedPrivateKey(
                                        symmetric_key.clone(),
                                    );
                                loop {
                                    if retry_count == 0 {
                                        return Err(Error::DeviceNotFound);
                                    }
                                    let credential_clone = credential.clone();
                                    let result = {
                                        let mut key_engine = self.key_engine.lock().await;
                                        aziot_dps_client_async::get_operation_status(
                                            global_endpoint.as_str(),
                                            &scope_id,
                                            &registration_id,
                                            &operation.operation_id,
                                            Some(symmetric_key.clone()),
                                            None,
                                            None,
                                            &self.key_client,
                                            &mut *key_engine,
                                            &self.cert_client,
                                        )
                                        .await
                                    };

                                    match result {
                                        Ok(reg_status) => {
                                            match reg_status.status {
                                                Some(status) => {
                                                    if !status.eq_ignore_ascii_case("assigning") {
                                                        let mut state = reg_status
                                                            .registration_state
                                                            .ok_or(Error::DeviceNotFound)?;
                                                        let iothub_hostname = state
                                                            .assigned_hub
                                                            .get_or_insert("".into());
                                                        let device_id = state
                                                            .device_id
                                                            .get_or_insert("".into());
                                                        let device =
                                                            aziot_identity_common::IoTHubDevice {
                                                                iothub_hostname: iothub_hostname
                                                                    .clone(),
                                                                device_id: device_id.clone(),
                                                                credentials: credential_clone,
                                                            };

                                                        break device;
                                                    }
                                                }
                                                None => return Err(Error::DeviceNotFound),
                                            };
                                        }
                                        Err(err) => return Err(Error::DPSClient(err)),
                                    }
                                    retry_count -= 1;
                                    tokio::time::delay_for(tokio::time::Duration::from_secs(
                                        DPS_ASSIGNMENT_RETRY_INTERVAL_SECS,
                                    ))
                                    .await;
                                }
                            }
                            Err(err) => return Err(Error::DPSClient(err)),
                        };

                        self.id_manager.set_device(&device);
                        aziot_identity_common::ProvisioningStatus::Provisioned(device)
                    }
                    settings::DpsAttestationMethod::X509 {
                        registration_id,
                        identity_cert,
                        identity_pk,
                    } => {
                        self.create_identity_cert_if_not_exist_or_expired(
                            KeyType::Handle(identity_pk.clone()),
                            &identity_cert,
                            &registration_id,
                            None,
                        )
                        .await?;

                        let result = {
                            let mut key_engine = self.key_engine.lock().await;
                            aziot_dps_client_async::register(
                                global_endpoint.as_str(),
                                &scope_id,
                                &registration_id,
                                None,
                                Some(identity_cert.clone()),
                                Some(identity_pk.clone()),
                                &self.key_client,
                                &mut *key_engine,
                                &self.cert_client,
                            )
                            .await
                        };

                        let device = match result {
                            Ok(operation) => {
                                let mut retry_count = (DPS_ASSIGNMENT_TIMEOUT_SECS
                                    / DPS_ASSIGNMENT_RETRY_INTERVAL_SECS)
                                    + 1;
                                let credential = aziot_identity_common::Credentials::X509 {
                                    identity_cert: identity_cert.clone(),
                                    identity_pk: identity_pk.clone(),
                                };
                                loop {
                                    if retry_count == 0 {
                                        return Err(Error::DeviceNotFound);
                                    }
                                    let credential_clone = credential.clone();
                                    let result = {
                                        let mut key_engine = self.key_engine.lock().await;
                                        aziot_dps_client_async::get_operation_status(
                                            global_endpoint.as_str(),
                                            &scope_id,
                                            &registration_id,
                                            &operation.operation_id,
                                            None,
                                            Some(identity_cert.clone()),
                                            Some(identity_pk.clone()),
                                            &self.key_client,
                                            &mut *key_engine,
                                            &self.cert_client,
                                        )
                                        .await
                                    };

                                    match result {
                                        Ok(reg_status) => {
                                            match reg_status.status {
                                                Some(status) => {
                                                    if !status.eq_ignore_ascii_case("assigning") {
                                                        let mut state = reg_status
                                                            .registration_state
                                                            .ok_or(Error::DeviceNotFound)?;
                                                        let iothub_hostname = state
                                                            .assigned_hub
                                                            .get_or_insert("".into());
                                                        let device_id = state
                                                            .device_id
                                                            .get_or_insert("".into());
                                                        let device =
                                                            aziot_identity_common::IoTHubDevice {
                                                                iothub_hostname: iothub_hostname
                                                                    .clone(),
                                                                device_id: device_id.clone(),
                                                                credentials: credential_clone,
                                                            };

                                                        break device;
                                                    }
                                                }
                                                None => return Err(Error::DeviceNotFound),
                                            };
                                        }
                                        Err(_) => return Err(Error::DeviceNotFound),
                                    }
                                    retry_count -= 1;
                                    tokio::time::delay_for(tokio::time::Duration::from_secs(
                                        DPS_ASSIGNMENT_RETRY_INTERVAL_SECS,
                                    ))
                                    .await;
                                }
                            }
                            Err(_) => return Err(Error::DeviceNotFound),
                        };

                        self.id_manager.set_device(&device);
                        aziot_identity_common::ProvisioningStatus::Provisioned(device)
                    }
                };
                device
            }
            settings::ProvisioningType::None => {
                log::info!("Skipping provisioning with IoT Hub.");

                aziot_identity_common::ProvisioningStatus::Unprovisioned
            }
        };
        Ok(device)
    }

    async fn issue_local_identity(
        &self,
        module_id: &str,
    ) -> Result<aziot_identity_common::Identity, Error> {
        let localid = self.settings.localid.as_ref().ok_or_else(|| {
            Error::Internal(InternalError::BadSettings(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no local id settings specified",
            )))
        })?;

        let local_identity =
            match self
                .local_identities
                .get(&aziot_identity_common::ModuleId(module_id.to_owned()))
            {
                None => {
                    return Err(Error::invalid_parameter(
                        "module_id",
                        format!("no local identity found for {}", module_id),
                    ))
                }
                Some(opts) => {
                    let attributes = opts.as_ref().map_or(
                        aziot_identity_common::LocalIdAttr::default(),
                        |opts| match opts {
                            settings::LocalIdOpts::X509 { attributes } => *attributes,
                        },
                    );

                    let subject = format!("{}.{}", module_id, localid.domain);
                    let (cert, key) = self
                        .create_identity_cert_if_not_exist_or_expired(
                            KeyType::Raw,
                            module_id,
                            subject.as_str(),
                            Some(attributes),
                        )
                        .await?;

                    aziot_identity_common::Identity::Local(aziot_identity_common::LocalIdSpec {
                        attr: attributes,
                        auth: aziot_identity_common::AuthenticationInfo {
                            auth_type: aziot_identity_common::AuthenticationType::X509,
                            key_handle: key,
                            cert_id: Some(cert),
                        },
                    })
                }
            };

        Ok(local_identity)
    }

    async fn create_identity_cert_if_not_exist_or_expired(
        &self,
        identity_pk: KeyType,
        identity_cert: &str,
        subject: &str,
        attributes: Option<aziot_identity_common::LocalIdAttr>,
    ) -> Result<(String, String), Error> {
        // Retrieve existing cert and check it for expiry. Raw key bytes are not persisted,
        // so a new cert must always be generated if KeyType is Raw.
        let mut device_id_cert = match identity_pk {
            KeyType::Raw => None,
            KeyType::Handle(_) => match self.cert_client.get_cert(identity_cert).await {
                Ok(pem) => {
                    let cert = openssl::x509::X509::from_pem(&pem).map_err(|err| {
                        Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                    })?;
                    let cert_expiration = cert.as_ref().not_after();
                    let current_time =
                        openssl::asn1::Asn1Time::days_from_now(0).map_err(|err| {
                            Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                        })?;
                    let expiration_time = current_time.diff(cert_expiration).map_err(|err| {
                        Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                    })?;

                    if expiration_time.days < 1 {
                        None
                    } else {
                        Some(pem)
                    }
                }
                Err(_) => None,
            },
        };

        // Retrieve private key for handles or generate new key bytes.
        let private_key = if device_id_cert.is_none() {
            let (key, key_string) = match identity_pk.clone() {
                KeyType::Handle(key_id) => {
                    let key_handle = self
                        .key_client
                        .create_key_pair_if_not_exists(&key_id, Some("rsa-2048:*"))
                        .await
                        .map_err(|err| {
                            Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                        })?;
                    let key_string = key_handle.0.clone();
                    let key_handle = std::ffi::CString::new(key_string.clone()).map_err(|err| {
                        Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                    })?;

                    let mut key_engine = self.key_engine.lock().await;
                    let key = key_engine.load_private_key(&key_handle).map_err(|err| {
                        Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                    })?;

                    (key, key_string)
                }
                KeyType::Raw => {
                    let rsa = openssl::rsa::Rsa::generate(2048).map_err(|err| {
                        Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                    })?;
                    let key = openssl::pkey::PKey::from_rsa(rsa).map_err(|err| {
                        Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                    })?;
                    let pem = key.private_key_to_pem_pkcs8().map_err(|err| {
                        Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                    })?;
                    let pem = std::string::String::from_utf8(pem).map_err(|err| {
                        Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                    })?;

                    (key, pem)
                }
            };

            let result = async {
                let csr = create_csr(&subject, &key, attributes).map_err(|err| {
                    Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                })?;

                let cert = self
                    .cert_client
                    .create_cert(&identity_cert, &csr, None)
                    .await
                    .map_err(|err| {
                        Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                    })?;
                device_id_cert = Some(cert);

                Ok::<(), Error>(())
            }
            .await;

            if let Err(err) = result {
                if let KeyType::Handle(_key_id) = identity_pk {
                    // TODO: need to delete key from keyd.
                }

                return Err(err);
            }

            key_string
        } else {
            match identity_pk {
                KeyType::Handle(key_id) => {
                    let key_handle =
                        self.key_client
                            .load_key_pair(&key_id)
                            .await
                            .map_err(|err| {
                                Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                            })?;

                    key_handle.0
                }
                KeyType::Raw => unreachable!(),
            }
        };

        // Convert device ID cert to String. Cannot fail because valid certificates are always
        // UTF-8 encodable characters.
        let device_id_cert = std::string::String::from_utf8(device_id_cert.unwrap()).unwrap();

        Ok((device_id_cert, private_key))
    }
}

fn create_csr(
    subject: &str,
    key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
    attributes: Option<aziot_identity_common::LocalIdAttr>,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    let mut csr = openssl::x509::X509Req::builder()?;

    csr.set_version(0)?;

    if let Some(attr) = attributes {
        let mut extensions: openssl::stack::Stack<openssl::x509::X509Extension> =
            openssl::stack::Stack::new()?;

        // basicConstraints = critical, CA:FALSE
        let basic_constraints = openssl::x509::extension::BasicConstraints::new()
            .critical()
            .build()?;
        extensions.push(basic_constraints)?;

        // keyUsage = digitalSignature, nonRepudiation, keyEncipherment
        let key_usage = openssl::x509::extension::KeyUsage::new()
            .critical()
            .digital_signature()
            .non_repudiation()
            .key_encipherment()
            .build()?;
        extensions.push(key_usage)?;

        // extendedKeyUsage = critical, clientAuth
        // Always set (even for servers) because it's required for EST client certificate renewal.
        let mut extended_key_usage = openssl::x509::extension::ExtendedKeyUsage::new();
        extended_key_usage.critical();
        extended_key_usage.client_auth();

        if attr == aziot_identity_common::LocalIdAttr::Server {
            // extendedKeyUsage = serverAuth (in addition to clientAuth)
            extended_key_usage.server_auth();
        }

        let extended_key_usage = extended_key_usage.build()?;
        extensions.push(extended_key_usage)?;

        csr.add_extensions(&extensions)?;
    }

    let mut subject_name = openssl::x509::X509Name::builder()?;
    subject_name.append_entry_by_nid(openssl::nid::Nid::COMMONNAME, subject)?;
    let subject_name = subject_name.build();
    csr.set_subject_name(&subject_name)?;
    csr.set_pubkey(key)?;
    csr.sign(key, openssl::hash::MessageDigest::sha256())?;

    let csr = csr.build();
    let csr = csr.to_pem()?;
    Ok(csr)
}

pub struct SettingsAuthorizer {
    pub pmap: std::collections::BTreeMap<crate::auth::Uid, crate::settings::Principal>,
    pub mset: std::collections::BTreeSet<aziot_identity_common::ModuleId>,
}

impl auth::authorization::Authorizer for SettingsAuthorizer {
    type Error = Error;

    fn authorize(&self, o: auth::Operation) -> Result<bool, Self::Error> {
        match o.op_type {
            crate::auth::OperationType::GetModule(m) => {
                if let crate::auth::AuthId::LocalPrincipal(creds) = o.auth_id {
                    if let Some(p) = self.pmap.get(&crate::auth::Uid(creds.0)) {
                        let allow_id_type = p.id_type.clone().map_or(false, |i| {
                            i.contains(&aziot_identity_common::IdType::Module)
                        });

                        return Ok(p.name.0 == m && allow_id_type);
                    }
                }
            }
            crate::auth::OperationType::GetDevice => {
                if let crate::auth::AuthId::LocalPrincipal(creds) = o.auth_id {
                    if let Some(p) = self.pmap.get(&crate::auth::Uid(creds.0)) {
                        let allow_id_type = p
                            .id_type
                            .clone()
                            .map_or(true, |i| i.contains(&aziot_identity_common::IdType::Device));

                        return Ok(allow_id_type);
                    }
                }
            }
            crate::auth::OperationType::CreateModule(m)
            | crate::auth::OperationType::UpdateModule(m)
            | crate::auth::OperationType::DeleteModule(m) => {
                if let crate::auth::AuthId::LocalPrincipal(creds) = o.auth_id {
                    if let Some(p) = self.pmap.get(&crate::auth::Uid(creds.0)) {
                        return Ok(p.id_type == None
                            && !self.mset.contains(&aziot_identity_common::ModuleId(m)));
                    }
                }
            }
            crate::auth::OperationType::GetTrustBundle => return Ok(true),
            crate::auth::OperationType::GetAllHubModules
            | crate::auth::OperationType::ReprovisionDevice => {
                if let crate::auth::AuthId::LocalPrincipal(creds) = o.auth_id {
                    if let Some(p) = self.pmap.get(&crate::auth::Uid(creds.0)) {
                        return Ok(p.id_type == None);
                    }
                }
            }
        }
        Ok(false)
    }
}

fn convert_to_map(
    principal: &[settings::Principal],
) -> (
    std::collections::BTreeMap<auth::Uid, settings::Principal>,
    std::collections::BTreeSet<aziot_identity_common::ModuleId>,
    std::collections::BTreeMap<aziot_identity_common::ModuleId, Option<settings::LocalIdOpts>>,
) {
    let mut local_mmap: std::collections::BTreeMap<
        aziot_identity_common::ModuleId,
        Option<settings::LocalIdOpts>,
    > = std::collections::BTreeMap::new();
    let mut module_mset: std::collections::BTreeSet<aziot_identity_common::ModuleId> =
        std::collections::BTreeSet::new();
    let mut pmap: std::collections::BTreeMap<auth::Uid, settings::Principal> =
        std::collections::BTreeMap::new();

    for p in principal {
        if let Some(id_type) = &p.id_type {
            for i in id_type {
                match i {
                    aziot_identity_common::IdType::Module => module_mset.insert(p.name.clone()),
                    aziot_identity_common::IdType::Local => local_mmap
                        .insert(p.name.clone(), p.localid.clone())
                        .is_none(),
                    _ => true,
                };
            }
        }

        pmap.insert(p.uid, p.clone());
    }

    (pmap, module_mset, local_mmap)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use aziot_identity_common::{IdType, LocalIdAttr, ModuleId};
    use http_common::Connector;

    use crate::auth::authorization::Authorizer;
    use crate::auth::{AuthId, Operation, OperationType, Uid};
    use crate::settings::{
        Endpoints, LocalId, LocalIdOpts, ManualAuthMethod, Principal, Provisioning,
        ProvisioningType, Settings,
    };
    use crate::SettingsAuthorizer;

    use super::{convert_to_map, Api};

    fn make_empty_settings() -> Settings {
        Settings {
            hostname: Default::default(),
            homedir: Default::default(),
            principal: Default::default(),
            provisioning: Provisioning {
                provisioning: ProvisioningType::Manual {
                    iothub_hostname: Default::default(),
                    device_id: Default::default(),
                    authentication: ManualAuthMethod::SharedPrivateKey {
                        device_id_pk: Default::default(),
                    },
                },
                dynamic_reprovisioning: Default::default(),
            },
            // Use unreachable endpoints for the defaults.
            endpoints: Endpoints {
                aziot_certd: Connector::Tcp {
                    host: "localhost".into(),
                    port: 0,
                },
                aziot_identityd: Connector::Tcp {
                    host: "localhost".into(),
                    port: 0,
                },
                aziot_keyd: Connector::Tcp {
                    host: "localhost".into(),
                    port: 0,
                },
            },
            localid: Default::default(),
        }
    }

    #[tokio::test]
    async fn init_identities_with_empty_args_exits_early() {
        let api = Api::new(
            make_empty_settings(),
            Box::new(|_| Ok(AuthId::Unknown)),
            Box::new(|_| Ok(true)),
        )
        .unwrap();

        let result = api
            .init_hub_identities(BTreeSet::new(), BTreeSet::new())
            .await;
        result.unwrap();
    }

    #[test]
    fn convert_to_map_creates_principal_lookup() {
        let local_p: Principal = Principal {
            uid: Uid(1000),
            name: ModuleId(String::from("local1")),
            id_type: Some(vec![IdType::Local]),
            localid: None,
        };
        let module_p: Principal = Principal {
            uid: Uid(1001),
            name: ModuleId(String::from("module1")),
            id_type: Some(vec![IdType::Module]),
            localid: None,
        };
        let v = vec![module_p.clone(), local_p.clone()];
        let (map, _, _) = convert_to_map(&v);

        assert!(map.contains_key(&Uid(1000)));
        assert_eq!(map.get(&Uid(1000)).unwrap(), &local_p);
        assert!(map.contains_key(&Uid(1001)));
        assert_eq!(map.get(&Uid(1001)).unwrap(), &module_p);
    }

    #[test]
    fn convert_to_map_module_sets() {
        let v = vec![
            Principal {
                uid: Uid(1000),
                name: ModuleId("hubmodule".to_owned()),
                id_type: Some(vec![IdType::Module]),
                localid: None,
            },
            Principal {
                uid: Uid(1001),
                name: ModuleId("localmodule".to_owned()),
                id_type: Some(vec![IdType::Local]),
                localid: None,
            },
            Principal {
                uid: Uid(1002),
                name: ModuleId("globalmodule".to_owned()),
                id_type: Some(vec![IdType::Module, IdType::Local]),
                localid: None,
            },
        ];

        let (_, hub_modules, local_modules) = convert_to_map(&v);

        assert!(hub_modules.contains(&ModuleId("hubmodule".to_owned())));
        assert!(hub_modules.contains(&ModuleId("globalmodule".to_owned())));
        assert!(!hub_modules.contains(&ModuleId("localmodule".to_owned())));

        assert!(local_modules.contains_key(&ModuleId("localmodule".to_owned())));
        assert!(local_modules.contains_key(&ModuleId("globalmodule".to_owned())));
        assert!(!local_modules.contains_key(&ModuleId("hubmodule".to_owned())));
    }

    #[test]
    fn settings_test() {
        let settings = Settings::new(Path::new("test/good_auth_settings.toml")).unwrap();

        let localid = settings.localid.unwrap();
        assert_eq!(
            localid,
            LocalId {
                domain: "example.com".to_owned(),
            }
        );

        let (map, _, _) = convert_to_map(&settings.principal);
        assert_eq!(map.len(), 3);
        assert!(map.contains_key(&Uid(1003)));
        assert_eq!(map.get(&Uid(1003)).unwrap().uid, Uid(1003));
        assert_eq!(
            map.get(&Uid(1003)).unwrap().name,
            ModuleId(String::from("hostprocess2"))
        );
        assert_eq!(
            map.get(&Uid(1003)).unwrap().id_type,
            Some(vec![IdType::Module, IdType::Local])
        );
    }

    #[test]
    fn local_id_opts() {
        let s = Settings::new(std::path::Path::new("test/good_local_opts.toml")).unwrap();

        assert_eq!(
            &s.principal,
            &[
                Principal {
                    uid: Uid(1000),
                    name: ModuleId("module1".to_owned()),
                    id_type: Some(vec![IdType::Local]),
                    localid: None,
                },
                Principal {
                    uid: Uid(1001),
                    name: ModuleId("module2".to_owned()),
                    id_type: Some(vec![IdType::Local]),
                    localid: Some(LocalIdOpts::X509 {
                        attributes: LocalIdAttr::default()
                    }),
                },
                Principal {
                    uid: Uid(1002),
                    name: ModuleId("module3".to_owned()),
                    id_type: Some(vec![IdType::Local]),
                    localid: Some(LocalIdOpts::X509 {
                        attributes: LocalIdAttr::Server
                    }),
                },
            ]
        );
    }

    #[test]
    fn empty_auth_settings_deny_any_action() {
        let (pmap, mset, _) = convert_to_map(&[]);
        let auth = SettingsAuthorizer { pmap, mset };
        let operation = Operation {
            auth_id: AuthId::Unknown,
            op_type: OperationType::CreateModule(String::default()),
        };

        let res = auth.authorize(operation);

        match res {
            Ok(false) => (),
            _ => panic!("incorrect authorization returned"),
        }
    }
}
