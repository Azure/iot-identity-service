// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_and_return,
    clippy::let_underscore_drop,
    clippy::let_unit_value,
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::type_complexity
)]
#![allow(dead_code)]

use std::sync::Arc;

use async_trait::async_trait;

use aziot_identityd_config as config;

pub mod auth;
pub mod configext;
pub mod error;
mod http;
pub mod identity;

use config_common::watcher::UpdateConfig;
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

#[derive(Debug)]
pub enum ReprovisionTrigger {
    ConfigurationFileUpdate,
    Api,
    Startup,
}

pub async fn main(
    settings: config::Settings,
    config_path: std::path::PathBuf,
    config_directory_path: std::path::PathBuf,
) -> Result<(http_common::Connector, http::Service), Box<dyn std::error::Error>> {
    let settings = settings.check().map_err(InternalError::BadSettings)?;

    let homedir_path = &settings.homedir;
    let connector = settings.endpoints.aziot_identityd.clone();

    if !homedir_path.exists() {
        let () =
            std::fs::create_dir_all(&homedir_path).map_err(error::InternalError::CreateHomeDir)?;
    }

    let api = Api::new(settings.clone())?;
    let api = Arc::new(futures_util::lock::Mutex::new(api));

    let api_startup = api.clone();
    let mut api_ = api_startup.lock().await;
    let _ = api_
        .update_config_inner(settings.clone(), ReprovisionTrigger::Startup)
        .await;

    config_common::watcher::start_watcher(config_path, config_directory_path, api.clone());

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

    key_client: Arc<aziot_key_client_async::Client>,
    key_engine: Arc<futures_util::lock::Mutex<openssl2::FunctionalEngine>>,
    cert_client: Arc<aziot_cert_client_async::Client>,
    tpm_client: Arc<aziot_tpm_client_async::Client>,
    proxy_uri: Option<hyper::Uri>,
}

impl Api {
    pub fn new(settings: config::Settings) -> Result<Self, Error> {
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

        let proxy_uri = http_common::get_proxy_uri(None)
            .map_err(|err| Error::Internal(InternalError::InvalidProxyUri(Box::new(err))))?;

        let id_manager = identity::IdentityManager::new(
            settings.homedir.clone(),
            key_client.clone(),
            key_engine.clone(),
            cert_client.clone(),
            tpm_client.clone(),
            None,
            proxy_uri.clone(),
        );

        Ok(Api {
            settings,
            authenticator: Box::new(auth::authentication::DefaultAuthenticator),
            authorizer: Box::new(auth::authorization::DefaultAuthorizer),
            id_manager,
            local_identities: Default::default(),

            key_client,
            key_engine,
            cert_client,
            tpm_client,
            proxy_uri,
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

    pub async fn reprovision_device(
        &mut self,
        auth_id: auth::AuthId,
        trigger: ReprovisionTrigger,
    ) -> Result<(), Error> {
        if !self.authorizer.authorize(auth::Operation {
            auth_id,
            op_type: auth::OperationType::ReprovisionDevice,
        })? {
            return Err(Error::Authorization);
        }

        log::info!("Provisioning starting. Reason: {:?}", trigger);

        let _ = match trigger {
            ReprovisionTrigger::ConfigurationFileUpdate => {
                self.id_manager
                    .provision_device(self.settings.provisioning.clone(), true)
                    .await?
            }
            ReprovisionTrigger::Api => {
                self.id_manager
                    .provision_device(self.settings.provisioning.clone(), false)
                    .await?
            }
            ReprovisionTrigger::Startup => {
                self.id_manager
                    .provision_device(
                        self.settings.provisioning.clone(),
                        !self.settings.provisioning.always_reprovision_on_startup,
                    )
                    .await?
            }
        };

        log::info!("Provisioning complete.");

        log::info!("Identity reconciliation started. Reason: {:?}", trigger);

        let _ = self
            .id_manager
            .reconcile_hub_identities(self.settings.clone())
            .await?;

        log::info!("Identity reconciliation complete.");

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

    async fn update_config_inner(
        &mut self,
        settings: config::Settings,
        trigger: ReprovisionTrigger,
    ) -> Result<(), Error> {
        let (allowed_users, _, local_modules) =
            configext::prepare_authorized_principals(&settings.principal);

        let authorizer = Box::new(SettingsAuthorizer {});
        self.authorizer = authorizer;

        // All uids in the principals are authenticated users to this service
        let authenticator = Box::new(SettingsAuthenticator {
            allowed_users: allowed_users.clone(),
        });
        self.authenticator = authenticator;
        self.local_identities = local_modules;

        let _ = self
            .reprovision_device(auth::AuthId::LocalRoot, trigger)
            .await?;

        self.settings = settings;

        Ok(())
    }
}

#[async_trait]
impl UpdateConfig for Api {
    type Config = config::Settings;
    type Error = Error;

    async fn update_config(&mut self, new_config: config::Settings) -> Result<(), Self::Error> {
        self.update_config_inner(new_config, ReprovisionTrigger::ConfigurationFileUpdate)
            .await
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
        //DEVNOTE: The authentication logic is ordered to lookup the principals first
        //         so that a host process can be configured to run as root.
        if let Some(p) = self.allowed_users.get(&credentials) {
            if p.id_type.is_some() {
                Ok(auth::AuthId::HostProcess(p.clone()))
            } else {
                Ok(auth::AuthId::Daemon)
            }
        } else if credentials == config::Uid(0) {
            Ok(auth::AuthId::LocalRoot)
        } else {
            Ok(auth::AuthId::Unknown)
        }
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
                        && p.id_type.map_or(false, |i| {
                            i.contains(&aziot_identity_common::IdType::Module)
                        })
                }
                auth::OperationType::GetDevice => p
                    .id_type
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use aziot_identity_common::{IdType, LocalIdAttr, LocalIdOpts, ModuleId};
    use aziot_identityd_config::{LocalId, Principal, Uid};

    use crate::auth::authorization::Authorizer;
    use crate::auth::{AuthId, Operation, OperationType};
    use crate::SettingsAuthorizer;

    use crate::configext::prepare_authorized_principals;

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
        let auth = SettingsAuthorizer {};
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
