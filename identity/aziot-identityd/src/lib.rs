// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::let_and_return,
    clippy::type_complexity
)]
#![allow(dead_code)]

pub mod app;
pub mod auth;
pub mod error;
pub mod identity;
mod logging;
pub mod settings;

pub use error::{Error, InternalError};

/// This is the interval at which to poll DPS for registration assignment status
const DPS_ASSIGNMENT_RETRY_INTERVAL_SECS: u64 = 10;

/// This is the number of seconds to wait for DPS to complete assignment to a hub
const DPS_ASSIGNMENT_TIMEOUT_SECS: u64 = 120;

pub struct Server {
    pub settings: settings::Settings,
    pub authenticator: Box<dyn auth::authentication::Authenticator<Error = Error> + Send + Sync>,
    pub authorizer: Box<dyn auth::authorization::Authorizer<Error = Error> + Send + Sync>,
    pub id_manager: identity::IdentityManager,

    key_client: std::sync::Arc<aziot_key_client_async::Client>,
    key_engine: std::sync::Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
    cert_client: std::sync::Arc<aziot_cert_client_async::Client>,
}

impl Server {
    pub fn new(
        settings: settings::Settings,
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

        Ok(Server {
            settings,
            authenticator,
            authorizer,
            id_manager,

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
        _idtype: &str,
        module_id: &str,
    ) -> Result<aziot_identity_common::Identity, Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::GetModule(String::from(module_id)),
        })? {
            return Err(Error::Authorization);
        }

        self.id_manager.get_module_identity(module_id).await
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
            match m {
                aziot_identity_common::Identity::Aziot(m) => {
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
        }

        for m in current_module_set {
            self.id_manager.create_module_identity(&m.0).await?;
            log::info!("Hub identity {:?} added", &m.0);
        }

        Ok(())
    }

    pub async fn init_local_identities(
        &self,
        mut prev_module_map: std::collections::BTreeMap<
            aziot_identity_common::ModuleId,
            Option<settings::LocalIdOpts>,
        >,
        current_module_map: std::collections::BTreeMap<
            aziot_identity_common::ModuleId,
            Option<settings::LocalIdOpts>,
        >,
    ) -> Result<(), Error> {
        if !current_module_map.is_empty() {
            let localid = self.settings.localid.as_ref().ok_or_else(|| {
                Error::Internal(InternalError::BadSettings(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "no local id settings specified",
                )))
            })?;

            // Create or renew local identity certificates for all modules in current.
            for id in &current_module_map {
                let module_id = &(id.0).0;
                let attributes =
                    id.1.as_ref()
                        .map_or(
                            aziot_identity_common::LocalIdAttr::default(),
                            |opts| match opts {
                                settings::LocalIdOpts::X509 { attributes } => *attributes,
                            },
                        );

                // Must reissue certificate if options changed.
                if let Some(prev_opts) = prev_module_map.remove_entry(id.0) {
                    if &prev_opts.1 == id.1 {
                        log::info!("Local identity {} up-to-date.", module_id);
                    } else {
                        log::info!("Options changed for {}. Reissuing certificate.", module_id);

                        self.cert_client
                            .delete_cert(module_id)
                            .await
                            .map_err(|err| {
                                Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                            })?;
                    }
                }

                let common_name = format!("{}.{}", module_id, localid.domain);
                self.create_identity_cert_if_not_exist_or_expired(
                    module_id,
                    module_id,
                    common_name.as_str(),
                    Some(attributes),
                )
                .await?;

                log::info!("Local identity {} ({}) registered.", module_id, attributes);
            }
        }

        // Remove local identities for modules in prev but not in current.
        for id in prev_module_map {
            let module_id = &(id.0).0;
            self.cert_client
                .delete_cert(module_id)
                .await
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
            // TODO: need to delete private key too.
            log::info!("Local identity {} removed.", module_id);
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
                            &identity_pk,
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
                            &identity_pk,
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

    async fn create_identity_cert_if_not_exist_or_expired(
        &self,
        identity_pk: &str,
        identity_cert: &str,
        subject: &str,
        attributes: Option<aziot_identity_common::LocalIdAttr>,
    ) -> Result<(), Error> {
        let device_id_cert = self.cert_client.get_cert(identity_cert).await;
        let create_cert = match device_id_cert {
            Ok(device_id_cert) => {
                let x509_req = openssl::x509::X509::from_pem(&device_id_cert).map_err(|err| {
                    Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                })?;
                let cert_expiration = x509_req.as_ref().not_after();
                let current_time = openssl::asn1::Asn1Time::days_from_now(0).map_err(|err| {
                    Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                })?;
                let expiration_time = current_time.diff(cert_expiration).map_err(|err| {
                    Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                })?;
                expiration_time.days < 1
            }
            Err(_) => true,
        };

        if create_cert {
            let identity_pk_key_handle = self
                .key_client
                .create_key_pair_if_not_exists(identity_pk, Some("rsa-2048:*"))
                .await
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
            // TODO: need to delete private key before returning if any function below fails.
            let csr = {
                let mut key_engine = self.key_engine.lock().await;

                let (identity_public_key, identity_private_key) = {
                    let identity_pk = std::ffi::CString::new(identity_pk_key_handle.0.clone())
                        .map_err(|err| {
                            Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                        })?;
                    let identity_public_key =
                        key_engine.load_public_key(&identity_pk).map_err(|err| {
                            Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                        })?;
                    let identity_private_key =
                        key_engine.load_private_key(&identity_pk).map_err(|err| {
                            Error::Internal(InternalError::CreateCertificate(Box::new(err)))
                        })?;

                    (identity_public_key, identity_private_key)
                };

                let csr = create_csr(
                    &subject,
                    &identity_public_key,
                    &identity_private_key,
                    attributes,
                )
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
                csr
            };

            let _new_cert = self
                .cert_client
                .create_cert(&identity_cert, &csr, None)
                .await
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
        }

        Ok(())
    }
}

fn create_csr(
    subject: &str,
    public_key: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
    private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
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
    csr.set_pubkey(public_key)?;
    csr.sign(private_key, openssl::hash::MessageDigest::sha256())?;

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

#[cfg(test)]
mod tests {
    use super::Server;
    use crate::{
        auth::AuthId,
        settings::{Endpoints, ManualAuthMethod, Provisioning, ProvisioningType, Settings},
    };
    use http_common::Connector;
    use std::collections::BTreeSet;

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
        let server = Server::new(
            make_empty_settings(),
            Box::new(|_| Ok(AuthId::Unknown)),
            Box::new(|_| Ok(true)),
        )
        .unwrap();

        let result = server
            .init_hub_identities(BTreeSet::new(), BTreeSet::new())
            .await;
        result.unwrap();
    }
}
