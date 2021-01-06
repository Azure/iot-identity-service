// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
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

use std::sync::Arc;

use aziot_identityd_config as config;

pub mod auth;
mod configext;
pub mod error;
mod http;
pub mod identity;

pub use error::{Error, InternalError};

/// URI query parameter that identifies module identity type.
const ID_TYPE_AZIOT: &str = "aziot";

/// URI query parameter that identifies local identity type.
const ID_TYPE_LOCAL: &str = "local";

macro_rules! match_id_type {
    ($id_type:ident { $( $type:ident => $action:block ,)+ }) => {
        if let Some(id_type) = $id_type {
            match id_type {
                $(
                    $type => $action,
                )+
                _ => Err(Error::invalid_parameter("type", format!("invalid type: {}", id_type))),
            }
        } else {
            Err(Error::invalid_parameter("type", "missing parameter"))
        }
    };
}

pub async fn main(
    settings: config::Settings,
) -> Result<(http_common::Connector, http::Service), Box<dyn std::error::Error>> {
    // Written to prev_settings_path if provisioning is successful.
    let settings = configext::check(settings)?;
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

    // let api = Api::new(
    //     settings.clone(),
    //     Default::default(),
    //     Box::new(auth::authentication::DefaultAuthenticator),
    //     Box::new(auth::authorization::DefaultAuthorizer),
    //     Default::default(),
    // )?;

    //new approach: file notifier and reprovision API do 2 things - authenticator.update() and trigger provision_device (which calls reconcile)
    //todo: Encapsulate into triggered task - triggered by file notification or provision device
    //todo: run this on each file notifier, using snapshot (clone) of new settings.principal
    let (allowed_users, hub_modules, local_modules) =
        prepare_authorized_principals(&settings.principal);

    //todo: wrap this up in update_authenticator
    // All uids in the principals are authenticated users to this service
    let authenticator = Box::new(SettingsAuthenticator {
        allowed_users: allowed_users.clone(),
    });

    //todo: try making this state agnostic and pass into Api object above
    let authorizer = Box::new(SettingsAuthorizer {});

    //todo: replace with update authenticator, authorizer, local_modules. Remove allowed users (replace with AuthId(Principal))
    let api = Api::new(
        settings,
        local_modules,
        authenticator,
        authorizer,
        allowed_users,
    )?;

    let api = Arc::new(futures_util::lock::Mutex::new(api));

    // {
    //     let mut api_ = api.lock().await;

    //     log::info!("Provisioning starting.");
    //     let provisioning = api_.provision_device().await?;
    //     log::info!("Provisioning complete.");

    //     let device_status = if let aziot_identity_common::ProvisioningStatus::Provisioned(device) =
    //         provisioning
    //     {
    //         let curr_hub_device_info = configext::HubDeviceInfo {
    //             hub_name: device.iothub_hostname,
    //             device_id: device.device_id,
    //         };
    //         let device_status = toml::to_string(&curr_hub_device_info)?;

    //         // Only consider the previous Hub modules if the current and previous Hub devices match.
    //         let prev_hub_modules = if prev_settings_path.exists() && prev_device_info_path.exists()
    //         {
    //             let prev_hub_device_info = configext::HubDeviceInfo::new(&prev_device_info_path)?;

    //             if prev_hub_device_info == Some(curr_hub_device_info) {
    //                 let prev_settings = configext::load_file(&prev_settings_path)?;
    //                 let (_, prev_hub_modules, _) =
    //                     prepare_authorized_principals(&prev_settings.principal);
    //                 prev_hub_modules
    //             } else {
    //                 std::collections::BTreeSet::default()
    //             }
    //         } else {
    //             std::collections::BTreeSet::default()
    //         };

    //         let () = api_
    //             .init_hub_identities(prev_hub_modules, hub_modules)
    //             .await?;
    //         log::info!("Identity reconciliation with IoT Hub complete.");

    //         device_status
    //     } else {
    //         configext::HubDeviceInfo::unprovisioned()
    //     };

    //     std::fs::write(prev_device_info_path, device_status)
    //         .map_err(error::InternalError::SaveDeviceInfo)?;
    //     let () = std::fs::write(prev_settings_path, &settings_serialized)
    //         .map_err(error::InternalError::SaveSettings)?;
    // }

    let service = http::Service { api };

    Ok((connector, service))
}

pub struct Api {
    pub settings: config::Settings,
    pub authenticator: Box<dyn auth::authentication::Authenticator<Error = Error> + Send + Sync>,
    pub authorizer: Box<dyn auth::authorization::Authorizer<Error = Error> + Send + Sync>,
    pub id_manager: identity::IdentityManager,
    pub local_identities: std::collections::BTreeMap<
        aziot_identity_common::ModuleId,
        Option<aziot_identity_common::LocalIdOpts>,
    >,
    pub caller_identities: std::collections::BTreeMap<config::Uid, config::Principal>,

    key_client: Arc<aziot_key_client_async::Client>,
    key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
    cert_client: Arc<aziot_cert_client_async::Client>,
    tpm_client: Arc<aziot_tpm_client_async::Client>,
}

impl Api {
    pub fn new(
        settings: config::Settings,
        local_identities: std::collections::BTreeMap<
            aziot_identity_common::ModuleId,
            Option<aziot_identity_common::LocalIdOpts>,
        >,
        authenticator: Box<dyn auth::authentication::Authenticator<Error = Error> + Send + Sync>,
        authorizer: Box<dyn auth::authorization::Authorizer<Error = Error> + Send + Sync>,
        caller_identities: std::collections::BTreeMap<config::Uid, config::Principal>,
    ) -> Result<Self, Error> {
        let key_service_connector = settings.endpoints.aziot_keyd.clone();

        let key_client = {
            let key_client = aziot_key_client_async::Client::new(
                aziot_key_common_http::ApiVersion::V2020_09_01,
                key_service_connector.clone(),
            );
            let key_client = Arc::new(key_client);
            key_client
        };

        let key_engine = {
            let key_client = aziot_key_client::Client::new(
                aziot_key_common_http::ApiVersion::V2020_09_01,
                key_service_connector,
            );
            let key_client = Arc::new(key_client);
            let key_engine = aziot_key_openssl_engine::load(key_client)
                .map_err(|err| Error::Internal(InternalError::LoadKeyOpensslEngine(err)))?;
            let key_engine = Arc::new(futures_util::lock::Mutex::new(key_engine));
            key_engine
        };

        let cert_client = {
            let cert_service_connector = settings.endpoints.aziot_certd.clone();
            let cert_client = aziot_cert_client_async::Client::new(
                aziot_cert_common_http::ApiVersion::V2020_09_01,
                cert_service_connector,
            );
            let cert_client = Arc::new(cert_client);
            cert_client
        };

        let tpm_client = {
            let tpm_service_connector = settings.endpoints.aziot_tpmd.clone();
            let tpm_client = aziot_tpm_client_async::Client::new(
                aziot_tpm_common_http::ApiVersion::V2020_09_01,
                tpm_service_connector,
            );
            let tpm_client = Arc::new(tpm_client);
            tpm_client
        };

        let id_manager = identity::IdentityManager::new(
            key_client.clone(),
            key_engine.clone(),
            cert_client.clone(),
            tpm_client.clone(),
            None,
        );

        Ok(Api {
            settings,
            authenticator,
            authorizer,
            id_manager,
            local_identities,
            caller_identities,

            key_client,
            key_engine,
            cert_client,
            tpm_client,
        })
    }

    pub async fn get_caller_identity(
        &self,
        auth_id: auth::AuthId,
    ) -> Result<aziot_identity_common::Identity, Error> {
        if self.authorizer.authorize(auth::Operation {
            auth_id: auth_id.clone(),
            op_type: auth::OperationType::GetDevice,
        })? {
            return self.id_manager.get_device_identity().await;
        } else if let crate::auth::AuthId::HostProcess(ref caller_principal) = auth_id {
            if self.authorizer.authorize(auth::Operation {
                auth_id: auth_id.clone(),
                op_type: auth::OperationType::GetModule(caller_principal.name.0.clone()),
            })? {
                return self
                    .id_manager
                    .get_module_identity(&caller_principal.name.0)
                    .await;
            }
        }

        return Err(Error::Authorization);
    }

    pub async fn get_identity(
        &self,
        auth_id: auth::AuthId,
        id_type: Option<&str>,
        module_id: &str,
    ) -> Result<aziot_identity_common::Identity, Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::GetModule(String::from(module_id)),
        })? {
            return Err(Error::Authorization);
        }

        match_id_type!(id_type {
            ID_TYPE_AZIOT => { self.id_manager.get_module_identity(module_id).await },
            ID_TYPE_LOCAL => {
                // Callers of this API must have a local identity specified in the principals list.
                match self
                    .local_identities
                    .get(&aziot_identity_common::ModuleId(module_id.to_owned())) {
                    Some(opts) => self.issue_local_identity(module_id, opts).await,
                    None => Err(
                        Error::invalid_parameter(
                            "moduleId",
                            format!("local identity for {} doesn't exist", module_id)
                        )
                    ),
                }
            },
        })
    }

    pub async fn get_identities(
        &self,
        auth_id: auth::AuthId,
        id_type: Option<&str>,
    ) -> Result<Vec<aziot_identity_common::Identity>, Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::GetAllHubModules,
        })? {
            return Err(Error::Authorization);
        }

        match_id_type!(id_type {
            ID_TYPE_AZIOT => { self.id_manager.get_module_identities().await },
        })
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
        id_type: Option<&str>,
        module_id: &str,
        opts: Option<aziot_identity_common_http::create_module_identity::CreateModuleOpts>,
    ) -> Result<aziot_identity_common::Identity, Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::CreateModule(String::from(module_id)),
        })? {
            return Err(Error::Authorization);
        }

        match_id_type!( id_type {
            ID_TYPE_AZIOT => { self.id_manager.create_module_identity(module_id).await },
            ID_TYPE_LOCAL => {
                if self.local_identities
                    .get(&aziot_identity_common::ModuleId(module_id.to_owned()))
                    .is_some() {
                    // Don't create a local identity for a module in the principals list.
                    Err(Error::invalid_parameter(
                        "moduleId",
                        format!("local identity for {} already exists", module_id)
                    ))
                } else {
                    let opts = opts.map(|opts| {
                        match opts {
                            aziot_identity_common_http::create_module_identity::CreateModuleOpts::LocalIdOpts(opts) => opts,
                            // Currently, the only supported opts variant is LocalIdOpts.
                            // But if more variants are added in the future, they should be rejected here.
                        }
                    });

                    self.issue_local_identity(module_id, &opts).await
                }
            },
        })
    }

    pub async fn update_identity(
        &self,
        auth_id: auth::AuthId,
        id_type: Option<&str>,
        module_id: &str,
    ) -> Result<aziot_identity_common::Identity, Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::UpdateModule(String::from(module_id)),
        })? {
            return Err(Error::Authorization);
        }

        match_id_type!(id_type {
            ID_TYPE_AZIOT => { self.id_manager.update_module_identity(module_id).await },
        })
    }

    pub async fn delete_identity(
        &self,
        auth_id: auth::AuthId,
        id_type: Option<&str>,
        module_id: &str,
    ) -> Result<(), Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::DeleteModule(String::from(module_id)),
        })? {
            return Err(Error::Authorization);
        }

        match_id_type!(id_type {
            ID_TYPE_AZIOT => { self.id_manager.delete_module_identity(module_id).await },
        })
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

        // let _ = self.provision_device().await?;
        Ok(())
    }

    async fn issue_local_identity(
        &self,
        module_id: &str,
        opts: &Option<aziot_identity_common::LocalIdOpts>,
    ) -> Result<aziot_identity_common::Identity, Error> {
        let localid = self.settings.localid.as_ref().ok_or_else(|| {
            Error::Internal(InternalError::BadSettings(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "no local id settings specified",
            )))
        })?;

        let local_identity = {
            let attributes =
                opts.as_ref()
                    .map_or(
                        aziot_identity_common::LocalIdAttr::default(),
                        |opts| match opts {
                            aziot_identity_common::LocalIdOpts::X509 { attributes } => *attributes,
                        },
                    );

            // Generate new private key for local identity.
            let rsa = openssl::rsa::Rsa::generate(2048)
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
            let private_key = openssl::pkey::PKey::from_rsa(rsa)
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
            let private_key_pem = private_key
                .private_key_to_pem_pkcs8()
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
            let private_key_pem = std::string::String::from_utf8(private_key_pem)
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
            let public_key = private_key
                .public_key_to_pem()
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
            let public_key = openssl::pkey::PKey::public_key_from_pem(&public_key)
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;

            // Create local identity CSR.
            let subject = format!(
                "{}.{}.{}",
                module_id, self.settings.hostname, localid.domain
            );
            let csr = create_csr(&subject, &public_key, &private_key, Some(attributes))
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
            let certificate = self
                .cert_client
                .create_cert(&module_id, &csr, None)
                .await
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
            let certificate = String::from_utf8(certificate)
                .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;

            // Parse certificate expiration time.
            let expiration = get_cert_expiration(&certificate)?;

            aziot_identity_common::Identity::Local(aziot_identity_common::LocalIdSpec {
                module_id: module_id.to_owned(),
                auth: aziot_identity_common::LocalAuthenticationInfo {
                    private_key: private_key_pem,
                    certificate,
                    expiration,
                },
            })
        };

        Ok(local_identity)
    }

    
}

pub(crate) fn create_csr(
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

pub struct SettingsAuthenticator {
    pub allowed_users: std::collections::BTreeMap<config::Uid, config::Principal>,
}

impl auth::authentication::Authenticator for SettingsAuthenticator {
    type Error = Error;

    fn authenticate(&self, credentials: config::Uid) -> Result<auth::AuthId, Self::Error> {
        if let Some(p) = self.allowed_users.get(&credentials) {
            if let Some(_) = p.id_type {
                return Ok(auth::AuthId::HostProcess(p.clone()));
            } else {
                return Ok(auth::AuthId::Daemon);
            }
        }

        Ok(auth::AuthId::Unknown)
    }
}

pub struct SettingsAuthorizer {}

impl auth::authorization::Authorizer for SettingsAuthorizer {
    type Error = Error;

    fn authorize(&self, o: auth::Operation) -> Result<bool, Self::Error> {
        match o.auth_id {
            crate::auth::AuthId::LocalRoot | crate::auth::AuthId::Daemon => Ok(true),
            crate::auth::AuthId::HostProcess(p) => Ok(match o.op_type {
                auth::OperationType::GetModule(m) => {
                    p.name.0 == m
                        && p.id_type.clone().map_or(false, |i| {
                            i.contains(&aziot_identity_common::IdType::Module)
                        })
                }
                auth::OperationType::GetDevice => p
                    .id_type
                    .clone()
                    .map_or(true, |i| i.contains(&aziot_identity_common::IdType::Device)),
                auth::OperationType::GetAllHubModules
                | auth::OperationType::CreateModule(_)
                | auth::OperationType::DeleteModule(_)
                | auth::OperationType::UpdateModule(_)
                | auth::OperationType::ReprovisionDevice => false,
                auth::OperationType::GetTrustBundle => true,
            }),
            crate::auth::AuthId::Unknown => {
                Ok(o.op_type == crate::auth::OperationType::GetTrustBundle)
            }
        }
    }
}

fn get_cert_expiration(cert: &str) -> Result<String, Error> {
    let cert = openssl::x509::X509::from_pem(cert.as_bytes())
        .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;

    let epoch = openssl::asn1::Asn1Time::from_unix(0).expect("unix epoch must be valid");
    let diff = epoch
        .diff(&cert.not_after())
        .map_err(|err| Error::Internal(InternalError::CreateCertificate(Box::new(err))))?;
    let diff = i64::from(diff.secs) + i64::from(diff.days) * 86400;
    let expiration = chrono::NaiveDateTime::from_timestamp(diff, 0);
    let expiration =
        chrono::DateTime::<chrono::Utc>::from_utc(expiration, chrono::Utc).to_rfc3339();

    Ok(expiration)
}

fn prepare_authorized_principals(
    principal: &[config::Principal],
) -> (
    std::collections::BTreeMap<config::Uid, config::Principal>,
    std::collections::BTreeSet<aziot_identity_common::ModuleId>,
    std::collections::BTreeMap<
        aziot_identity_common::ModuleId,
        Option<aziot_identity_common::LocalIdOpts>,
    >,
) {
    let mut local_module_map: std::collections::BTreeMap<
        aziot_identity_common::ModuleId,
        Option<aziot_identity_common::LocalIdOpts>,
    > = std::collections::BTreeMap::new();
    let mut hub_module_set: std::collections::BTreeSet<aziot_identity_common::ModuleId> =
        std::collections::BTreeSet::new();
    let mut principal_map: std::collections::BTreeMap<config::Uid, config::Principal> =
        std::collections::BTreeMap::new();
    let mut found_daemon = false;

    for p in principal {
        if let Some(id_type) = &p.id_type {
            for i in id_type {
                match i {
                    aziot_identity_common::IdType::Module => hub_module_set.insert(p.name.clone()),
                    aziot_identity_common::IdType::Local => local_module_map
                        .insert(p.name.clone(), p.localid.clone())
                        .is_some(),
                    _ => true,
                };
            }
        } else if found_daemon {
            log::warn!("Principal {:?} is not authorized. Please ensure there is only one principal without a type in the config.toml", p.name);
            continue;
        } else {
            found_daemon = true
        }

        principal_map.insert(p.uid, p.clone());
    }

    (principal_map, hub_module_set, local_module_map)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use aziot_identity_common::{IdType, LocalIdAttr, LocalIdOpts, ModuleId};
    use aziot_identityd_config::{
        LocalId, Principal,
        Uid,
    };

    use crate::auth::authorization::Authorizer;
    use crate::auth::{AuthId, Operation, OperationType};
    use crate::SettingsAuthorizer;

    use super::prepare_authorized_principals;

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
        let (map, _, _) = prepare_authorized_principals(&v);

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

        let (_, hub_modules, local_modules) = prepare_authorized_principals(&v);

        assert!(hub_modules.contains(&ModuleId("hubmodule".to_owned())));
        assert!(hub_modules.contains(&ModuleId("globalmodule".to_owned())));
        assert!(!hub_modules.contains(&ModuleId("localmodule".to_owned())));

        assert!(local_modules.contains_key(&ModuleId("localmodule".to_owned())));
        assert!(local_modules.contains_key(&ModuleId("globalmodule".to_owned())));
        assert!(!local_modules.contains_key(&ModuleId("hubmodule".to_owned())));
    }

    #[test]
    fn settings_test() {
        let settings =
            super::configext::load_file(Path::new("test/good_auth_settings.toml")).unwrap();

        let localid = settings.localid.unwrap();
        assert_eq!(
            localid,
            LocalId {
                domain: "example.com".to_owned(),
            }
        );

        let (map, _, _) = prepare_authorized_principals(&settings.principal);
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
        let s =
            super::configext::load_file(std::path::Path::new("test/good_local_opts.toml")).unwrap();

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
        let auth = SettingsAuthorizer {
        };
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
