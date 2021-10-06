// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_and_return,
    clippy::let_unit_value,
    clippy::missing_errors_doc,
    clippy::similar_names,
    clippy::too_many_lines
)]

mod error;
mod est;
mod http;

use error::{Error, InternalError};

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::ffi::CString;
use std::fs::{read, remove_file, write};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use aziot_certd_config::{
    CertIssuance, CertIssuanceMethod, CertIssuanceOptions, CertSubject, Config, Endpoints, EstAuthBasic,
    EstAuthX509, CertAuthority, PreloadedCert, Principal,
};
use aziot_key_common::KeyHandle;
use config_common::watcher::UpdateConfig;
use http_common::{Connector, get_proxy_uri};

use futures_util::lock::Mutex;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::x509::{X509, X509Name, X509NameRef, X509Req};
use std::path::{Path, PathBuf};

#[allow(clippy::unused_async)]
pub async fn main(
    config: Config,
    config_path: PathBuf,
    config_directory_path: PathBuf,
) -> Result<(Connector, http::Service), Box<dyn StdError>> {
    let Config {
        homedir_path,
        cert_issuance,
        preloaded_certs,
        endpoints:
            Endpoints {
                aziot_certd: connector,
                aziot_keyd: key_connector,
            },
        principal,
    } = config;

    let api = {
        let key_client = {
            let key_client = aziot_key_client::Client::new(
                aziot_key_common_http::ApiVersion::V2021_05_01,
                key_connector,
            );
            let key_client = Arc::new(key_client);
            key_client
        };

        let key_engine = aziot_key_openssl_engine::load(key_client.clone())
            .map_err(|err| Error::Internal(InternalError::LoadKeyOpensslEngine(err)))?;

        let proxy_uri = get_proxy_uri(None)
            .map_err(|err| Error::Internal(InternalError::InvalidProxyUri(Box::new(err))))?;

        Api {
            homedir_path,
            cert_issuance,
            preloaded_certs,
            principals: principal_to_map(principal),

            key_client,
            key_engine,
            proxy_uri,
        }
    };
    let api = Arc::new(Mutex::new(api));

    config_common::watcher::start_watcher(config_path, config_directory_path, api.clone());

    let service = http::Service { api };

    Ok((connector, service))
}

struct Api {
    homedir_path: PathBuf,
    cert_issuance: CertIssuance,
    preloaded_certs: BTreeMap<String, PreloadedCert>,
    principals: BTreeMap<libc::uid_t, Vec<wildmatch::WildMatch>>,

    key_client: Arc<aziot_key_client::Client>,
    key_engine: openssl2::FunctionalEngine,
    proxy_uri: Option<hyper::Uri>,
}

impl Api {
    pub async fn create_cert(
        this: Arc<Mutex<Self>>,
        id: String,
        csr: Vec<u8>,
        issuer: Option<(String, aziot_key_common::KeyHandle)>,
        user: libc::uid_t,
    ) -> Result<Vec<u8>, Error> {
        let mut this = this.lock().await;

        if !this.authorize(user, &id) {
            return Err(Error::Unauthorized(user, id));
        }

        let x509 = create_cert(
            &mut *this,
            id,
            csr,
            issuer
                .map(|(issuer_cert, issuer_private_key)| (issuer_cert, issuer_private_key)),
        )
        .await?;

        Ok(x509)
    }

    pub fn import_cert(&mut self, id: &str, pem: &[u8], user: libc::uid_t) -> Result<(), Error> {
        if !self.authorize(user, id) {
            return Err(Error::Unauthorized(user, id.to_string()));
        }

        let path =
            aziot_certd_config::util::get_path(&self.homedir_path, &self.preloaded_certs, id, true)
                .map_err(|err| Error::Internal(InternalError::GetPath(err)))?;
        write(path, pem)
            .map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
        Ok(())
    }

    pub fn get_cert(&mut self, id: &str) -> Result<Vec<u8>, Error> {
        let bytes = get_cert_inner(&self.homedir_path, &self.preloaded_certs, id)?
            .ok_or_else(|| Error::invalid_parameter("id", "not found"))?;
        Ok(bytes)
    }

    pub fn delete_cert(&mut self, id: &str, user: libc::uid_t) -> Result<(), Error> {
        if !self.authorize(user, id) {
            return Err(Error::Unauthorized(user, id.to_string()));
        }

        let path =
            aziot_certd_config::util::get_path(&self.homedir_path, &self.preloaded_certs, id, true)
                .map_err(|err| Error::Internal(InternalError::GetPath(err)))?;
        match remove_file(path) {
            Ok(()) => Ok(()),
            Err(ref err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(Error::Internal(InternalError::DeleteFile(err))),
        }
    }

    fn authorize(&self, user: libc::uid_t, id: &str) -> bool {
        // Root user is always authorized.
        if user == 0 {
            return true;
        }

        // Authorize user based on stored principals config.
        if let Some(certs) = self.principals.get(&user) {
            return certs.iter().any(|cert| cert.is_match(id));
        }

        false
    }
}

#[async_trait]
impl UpdateConfig for Api {
    type Config = Config;
    type Error = Error;

    #[allow(clippy::unused_async)]
    async fn update_config(&mut self, new_config: Self::Config) -> Result<(), Self::Error> {
        log::info!("Detected change in config files. Updating config.");

        // Don't allow changes to homedir path or endpoints while daemon is running.
        // Only update other fields.
        let Config {
            cert_issuance,
            preloaded_certs,
            principal,
            ..
        } = new_config;
        self.cert_issuance = cert_issuance;
        self.preloaded_certs = preloaded_certs;
        self.principals = principal_to_map(principal);

        log::info!("Config update finished.");
        Ok(())
    }
}

fn load_inner(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    match read(path) {
        Ok(cert_bytes) => Ok(Some(cert_bytes)),
        Err(ref err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::Internal(InternalError::ReadFile(err))),
    }
}

fn build_name(subj: &CertSubject) -> Result<X509Name, Error> {
    let mut builder = X509Name::builder()
        .map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

    match subj {
        CertSubject::CommonName(cn) =>
            builder
                .append_entry_by_text("CN", &cn)
                .map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?,
        CertSubject::Subject(fields) =>
            for (name, value) in fields.iter() {
                builder
                    .append_entry_by_text(name, value)
                    .map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
            }
    }

    Ok(builder.build())
}

fn validate_csr(csr: &[u8]) -> Result<(X509Req, PKey<Public>), Box<dyn StdError + Send + Sync>> {
    let x509_req = X509Req::from_pem(csr)?;
    let x509_req_public_key = x509_req.public_key()?;

    if !x509_req.verify(&x509_req_public_key)? {
        Err("CSR failed to be verified with its public key".into())
    }
    else {
        Ok((x509_req, x509_req_public_key))
    }
}

struct Issuer<'a> {
    path: &'a Path,
    id: &'a str,
    key: &'a KeyHandle
}

fn create_with_issuer(
    key_engine: &mut openssl2::FunctionalEngine,
    id: &str,
    csr: &[u8],
    expiry: Option<u32>,
    subject_override: Option<&CertSubject>,
    issuer: Issuer<'_>
) -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
    let (req, pubkey) = validate_csr(csr)
        .map_err(|err| Error::invalid_parameter("csr", err))?;

    let expiry = expiry.unwrap_or(30);

    let subject_override = subject_override
        .map(build_name)
        .transpose()?;

    let subject_name = subject_override.as_deref()
        .unwrap_or_else(|| req.subject_name());

    let issuer_privkey = CString::new(issuer.key.0.to_owned())
        .map_err(|err| Error::invalid_parameter("issuer.privateKeyHandle", err))?;

    let issuer_privkey = key_engine
        .load_private_key(&issuer_privkey)
        .map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(subject_name)?;
    builder.set_pubkey(&pubkey)?;
    builder.set_not_before(&*Asn1Time::days_from_now(0)?)?;

    let _ = req.extensions()
        .map(|exts| -> Result<_, Box<dyn StdError + Send + Sync>> {
            for ext in exts {
                builder.append_extension(ext)?
            }
            Ok(())
        })
        .ok()
        .transpose()?;

    let expiry = &*Asn1Time::days_from_now(expiry)?;

    let issuer_x509_stack: Vec<X509>;
    let (issuer_name, min_expiry, issuer_pem) = if id != issuer.id {
        let issuer_x509_pem = load_inner(issuer.path)?
            .ok_or_else(|| Error::invalid_parameter("issuer.certId", "not found"))?;
        issuer_x509_stack = X509::stack_from_pem(&issuer_x509_pem)?;

        let issuer_x509 = issuer_x509_stack
            .get(0)
            .ok_or_else(|| Error::invalid_parameter("issuer.certId", "invalid issuer"))?;

        let issuer_expiry = issuer_x509.not_after();

        ( issuer_x509.subject_name()
        , if expiry < issuer_expiry { expiry } else { issuer_expiry }
        , Some(issuer_x509_pem)
        )
    }
    else {
        (subject_name, expiry, None)
    };

    builder.set_not_after(min_expiry)?;
    builder.set_issuer_name(issuer_name)?;
    builder.sign(&issuer_privkey, MessageDigest::sha256())?;

    let mut x509 = builder.build()
        .to_pem()?;

    if let Some(pem) = issuer_pem.as_ref() {
        x509.extend_from_slice(pem)
    }

    Ok(x509)
}

async fn create_cert_tmp(
    api: &mut Api,
    id: String,
    csr: Vec<u8>,
    issuer: Option<(String, KeyHandle)>
) -> Result<Vec<u8>, Error> {
    // Hints for borrow checker
    let cert_issuance = &api.cert_issuance;
    let homedir_path = &api.homedir_path;
    let preloaded_certs = &api.preloaded_certs;
    let mut key_engine = &mut api.key_engine;

    let cert_options = cert_issuance.certs.get(&id);

    let mut create_with_issuer = |issuer: &(String, KeyHandle)| -> Result<Vec<u8>, Box<dyn StdError + Send + Sync>> {
        let expiry = &*Asn1Time::days_from_now(
                cert_options
                    .and_then(|opts| opts.expiry_days)
                    .unwrap_or(30)
            )?;
        let name_override = cert_options
            .and_then(|opts| opts.subject.as_ref())
            .map(build_name)
            .transpose()?;

        let (req, pubkey) = validate_csr(&csr)
            .map_err(|err| Error::invalid_parameter("csr", err))?;

        let subject_name = name_override.as_deref()
            .unwrap_or_else(|| req.subject_name());

        let issuer_privkey = CString::new(issuer.1.0.to_owned())
            .map_err::<Box<dyn StdError + Send + Sync>, _>(|err| Error::invalid_parameter("issuer.privateKeyHandle", err).into())
            .and_then(|pk|
                key_engine
                    .load_private_key(&pk)
                    .map_err(Into::into)
            )?;

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(subject_name)?;
        builder.set_pubkey(&pubkey)?;
        builder.set_not_before(&*Asn1Time::days_from_now(0)?)?;

        let _ = req.extensions()
            .map(|exts| -> Result<_, Box<dyn StdError + Send + Sync>> {
                for ext in exts {
                    builder.append_extension(ext)?
                }
                Ok(())
            })
            .ok()
            .transpose()?;

        let issuer_x509_stack: Vec<X509>;
        let (issuer_name, min_expiry, issuer_pem) = if &id != &issuer.0 {
            let issuer_path = aziot_certd_config::util::get_path(
                    homedir_path,
                    preloaded_certs,
                    &issuer.0,
                    true
                )?;
            let issuer_x509_pem = load_inner(&issuer_path)?
                .ok_or_else(|| Error::invalid_parameter("issuer.certId", "not found"))?;
            issuer_x509_stack = X509::stack_from_pem(&issuer_x509_pem)?;

            let issuer_x509 = issuer_x509_stack
                .get(0)
                .ok_or_else(|| Error::invalid_parameter("issuer.certId", "invalid issuer"))?;

            let issuer_expiry = issuer_x509.not_after();

            ( issuer_x509.subject_name()
            , if expiry < issuer_expiry { expiry } else { issuer_expiry }
            , Some(issuer_x509_pem)
            )
        }
        else {
            (subject_name, expiry, None)
        };

        builder.set_not_after(min_expiry)?;
        builder.set_issuer_name(issuer_name)?;
        builder.sign(&issuer_privkey, MessageDigest::sha256())?;

        let mut x509 = builder.build()
            .to_pem()?;

        if let Some(pem) = issuer_pem.as_ref() {
            x509.extend_from_slice(pem)
        }

        Ok(x509)
    };

    if let Some(ref issuer) = issuer {
        create_with_issuer(issuer)
            .map_err(|err| Error::Internal(InternalError::CreateCert(err.into())))
    }
    else {
        // Hint for borrow checker
        let key_client = &api.key_client;

        let cert_options = cert_options
            .ok_or_else(||
                Error::invalid_parameter(
                    "issuer",
                    "issuer is required for locally-issued certificates"
                )
            )?;

        (match &cert_options.method {
            CertIssuanceMethod::SelfSigned =>
                key_client
                    .load_key_pair(&id)
                    .map_err(Into::into)
                    .and_then(|pk| create_with_issuer(&(id.clone(), pk))),
            CertIssuanceMethod::LocalCa =>
                cert_issuance.local_ca
                    .as_ref()
                    .ok_or_else::<Box<dyn StdError + Send + Sync>, _>(||
                        format!(
                            "cert {:?} is configured to be issued by local CA, but local CA is not configured",
                            id
                        ).into()
                    )
                    .and_then(|CertAuthority { cert, pk }|
                        key_client
                            .load_key_pair(&pk)
                            .map(|pk| (cert.clone(), pk))
                            .map_err(Into::into)
                    )
                    .and_then(|issuer| create_with_issuer(&issuer)),
            CertIssuanceMethod::Est { url, auth } => {
                Ok(vec![])
            }
        }).map_err(|err| Error::Internal(InternalError::CreateCert(err.into())))
    }
}

fn create_cert<'a>(
    api: &'a mut Api,
    id: String,
    csr: Vec<u8>,
    issuer: Option<(String, KeyHandle)>,
) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, Error>> + Send + 'a>> {

    // Creating a cert is recursive in some cases. An async fn cannot recurse because its RPIT Future type would end up being infinitely sized,
    // so it needs to be boxed. So we have a non-async fn returning a boxed future, where the future being boxed is the result of an inner asyn fn,
    // and the recursive call is for the outer boxed-future-returning fn.

    async fn create_cert_inner(
        api: &mut Api,
        id: String,
        csr: Vec<u8>,
        issuer: Option<(String, KeyHandle)>,
    ) -> Result<Vec<u8>, Error> {
        // Look up issuance options for this certificate ID.
        let cert_options = api.cert_issuance.certs.get(&id).to_owned();
        let method = cert_options.map(|opts| &opts.method);

        if let Some((issuer_id, issuer_private_key)) = issuer {
            // Issuer is explicitly specified, so load it and use it to sign the CSR.

            let issuer_path = aziot_certd_config::util::get_path(
                    &api.homedir_path,
                    &api.preloaded_certs,
                    &issuer_id,
                    true
                )
                .map_err(|err| Error::Internal(InternalError::GetPath(err)))?;

            // If issuance options are not provided for this certificate ID, use defaults.
            let expiry_days = cert_options
                .and_then(|opts| opts.expiry_days);

            let name_override = cert_options
                .and_then(|opts| opts.subject.as_ref());

            let issuer_params = Issuer {
                path: &issuer_path,
                id: &issuer_id,
                key: &issuer_private_key
            };

            let x509 = create_with_issuer(
                    &mut api.key_engine,
                    &id,
                    &csr,
                    expiry_days,
                    name_override,
                    issuer_params
                ).map_err(|err| Error::Internal(InternalError::CreateCert(err.into())))?;

            let path = aziot_certd_config::util::get_path(
                    &api.homedir_path,
                    &api.preloaded_certs,
                    &id,
                    true,
                )
                .map_err(|err| Error::Internal(InternalError::GetPath(err)))?;
            write(path, &x509)
                .map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

            Ok(x509)
        }
        else {
            // Issuer is not explicitly specified, so use the issuance options for this cert from the configuration.

            let cert_options: &CertIssuanceOptions = cert_options.ok_or_else(|| {
                Error::invalid_parameter("issuer", "issuer is required for locally-issued certs")
            })?;

            match &cert_options.method {
                CertIssuanceMethod::Est {
                    url: cert_url,
                    auth: cert_auth,
                } => {
                    let defaults = api.cert_issuance.est.as_ref();

                    let auth = cert_auth.as_ref().or_else(|| {
                        defaults.map(|default| &default.auth)
                    }).ok_or_else(|| {
                        Error::Internal(InternalError::CreateCert(
                            format!(
                                "cert {:?} is configured to be issued by EST, but EST auth is not configured",
                                id,
                            )
                            .into(),
                        ))
                    })?;

                    let url = cert_url.as_ref().or_else(|| {
                        defaults
                            .map(|default| &default.urls)
                            .and_then(|urls| urls.get(&id).or_else(|| urls.get("default")))
                    }).ok_or_else(|| {
                        Error::Internal(InternalError::CreateCert(
                            format!(
                                "cert {:?} is configured to be issued by EST, but EST URL is not configured",
                                id,
                            )
                            .into(),
                        ))
                    })?;

                    let headers = auth
                        .headers
                        .clone()
                        .unwrap_or_default();

                    let auth_basic = auth
                        .basic
                        .as_ref()
                        .map(|EstAuthBasic { username, password }| (&**username, &**password));

                    let mut trusted_certs_x509 = vec![];

                    if let Some(default) = defaults {
                        for trusted_cert in &default.trusted_certs {
                            let pem =
                                get_cert_inner(&api.homedir_path, &api.preloaded_certs, trusted_cert)?
                                    .ok_or_else(|| {
                                        Error::Internal(InternalError::CreateCert(
                                            format!(
                                        "cert_issuance.est.trusted_certs contains unreadable cert {:?}",
                                        trusted_cert,
                                    )
                                            .into(),
                                        ))
                                    })?;
                            let x509 =
                                X509::stack_from_pem(&pem).map_err(|err| {
                                    Error::Internal(InternalError::CreateCert(Box::new(err)))
                                })?;
                            trusted_certs_x509.extend(x509);
                        }
                    }

                    if let Some(EstAuthX509 {
                        identity: CertAuthority { cert: identity_cert, pk: identity_private_key },
                        bootstrap_identity
                    }) = &auth.x509
                    {
                        // We need to use TLS client cert auth with the EST server.
                        //
                        // Try to load the EST identity cert.

                        let identity = match get_cert_inner(
                            &api.homedir_path,
                            &api.preloaded_certs,
                            identity_cert,
                        ) {
                            Ok(Some(identity_cert)) => {
                                match api.key_client.load_key_pair(identity_private_key) {
                                    Ok(identity_private_key) => {
                                        Ok((identity_cert, identity_private_key))
                                    }
                                    Err(err) => Err(format!(
                                        "could not get EST identity cert private key: {}",
                                        err
                                    )),
                                }
                            }
                            Ok(None) => Err(format!(
                                "could not get EST identity cert: {}",
                                io::Error::from(io::ErrorKind::NotFound)
                            )),
                            Err(err) => Err(format!("could not get EST identity cert: {}", err)),
                        };

                        match identity {
                            Ok((identity_cert, identity_private_key)) => {
                                let identity_private_key =
                                    CString::new(identity_private_key.0.clone())
                                        .map_err(|err| {
                                            Error::Internal(InternalError::CreateCert(Box::new(
                                                err,
                                            )))
                                        })?;
                                let identity_private_key = api
                                    .key_engine
                                    .load_private_key(&identity_private_key)
                                    .map_err(|err| {
                                        Error::Internal(InternalError::CreateCert(Box::new(err)))
                                    })?;

                                let x509 = est::create_cert(
                                    csr.to_owned(),
                                    url,
                                    &headers,
                                    auth_basic,
                                    Some((&identity_cert, &identity_private_key)),
                                    trusted_certs_x509,
                                    api.proxy_uri.clone(),
                                )
                                .await?;

                                let path = aziot_certd_config::util::get_path(
                                    &api.homedir_path,
                                    &api.preloaded_certs,
                                    &id,
                                    true,
                                )
                                .map_err(|err| Error::Internal(InternalError::GetPath(err)))?;
                                write(path, &x509).map_err(|err| {
                                    Error::Internal(InternalError::CreateCert(Box::new(err)))
                                })?;

                                Ok(x509)
                            }

                            Err(identity_err) => {
                                // EST identity cert could not be loaded. We need to issue a new one using the EST bootstrap identity cert.
                                let bootstrap_identity = if let Some(CertAuthority {
                                    cert: bootstrap_identity_cert,
                                    pk: bootstrap_identity_private_key,
                                }) = bootstrap_identity
                                {
                                    match get_cert_inner(&api.homedir_path, &api.preloaded_certs, bootstrap_identity_cert) {
                                        Ok(Some(bootstrap_identity_cert)) => match api.key_client.load_key_pair(bootstrap_identity_private_key) {
                                            Ok(bootstrap_identity_private_key) => Ok((bootstrap_identity_cert, bootstrap_identity_private_key)),
                                            Err(err) => Err(format!("could not get EST bootstrap identity cert private key: {}", err)),
                                        },

                                        Ok(None) => Err(format!(
                                            "could not get EST bootstrap identity cert: {}",
                                            io::Error::from(io::ErrorKind::NotFound),
                                        )),

                                        Err(err) => Err(format!("could not get EST bootstrap identity cert: {}", err)),
                                    }
                                }
                                else {
                                    Err(format!(
                                        "cert {:?} is configured to be issued by EST, \
                                        but EST identity could not be obtained \
                                        and EST bootstrap identity is not configured; {}",
                                        id, identity_err,
                                    ))
                                };

                                match bootstrap_identity {
                                    Ok((
                                        bootstrap_identity_cert,
                                        bootstrap_identity_private_key,
                                    )) => {
                                        // Create a CSR for the new EST identity cert.

                                        if let Ok(identity_key_pair_handle) =
                                            api.key_client.load_key_pair(identity_private_key)
                                        {
                                            api.key_client
                                                .delete_key_pair(&identity_key_pair_handle)
                                                .map_err(|err| {
                                                    Error::Internal(InternalError::CreateCert(
                                                        Box::new(err),
                                                    ))
                                                })?;
                                        }

                                        let identity_key_pair_handle = api
                                            .key_client
                                            .create_key_pair_if_not_exists(
                                                identity_private_key,
                                                Some("ec-p256:rsa-4096:*"),
                                            )
                                            .map_err(|err| {
                                                Error::Internal(InternalError::CreateCert(
                                                    Box::new(err),
                                                ))
                                            })?;

                                        let (identity_public_key, identity_private_key) = {
                                            let identity_key_pair_handle = CString::new(
                                                identity_key_pair_handle.0.clone(),
                                            )
                                            .map_err(|err| {
                                                Error::Internal(InternalError::CreateCert(
                                                    Box::new(err),
                                                ))
                                            })?;
                                            let identity_public_key = api
                                                .key_engine
                                                .load_public_key(&identity_key_pair_handle)
                                                .map_err(|err| {
                                                    Error::Internal(InternalError::CreateCert(
                                                        Box::new(err),
                                                    ))
                                                })?;
                                            let identity_private_key = api
                                                .key_engine
                                                .load_private_key(&identity_key_pair_handle)
                                                .map_err(|err| {
                                                    Error::Internal(InternalError::CreateCert(
                                                        Box::new(err),
                                                    ))
                                                })?;
                                            (identity_public_key, identity_private_key)
                                        };

                                        let mut identity_csr = openssl::x509::X509Req::builder()
                                            .map_err(|err| {
                                                Error::Internal(InternalError::CreateCert(
                                                    Box::new(err),
                                                ))
                                            })?;

                                        identity_csr.set_version(0).map_err(|err| {
                                            Error::Internal(InternalError::CreateCert(Box::new(
                                                err,
                                            )))
                                        })?;

                                        let mut subject_name = openssl::x509::X509Name::builder()
                                            .map_err(|err| {
                                            Error::Internal(InternalError::CreateCert(Box::new(
                                                err,
                                            )))
                                        })?;

                                        let common_name = "est-id";
                                            /*
                                            cert_options.subject
                                                .unwrap_or(CertSubject::CommonName("est-id".to_owned()));
                                            */

                                        subject_name
                                            .append_entry_by_text("CN", common_name)
                                            .map_err(|err| {
                                                Error::Internal(InternalError::CreateCert(
                                                    Box::new(err),
                                                ))
                                            })?;
                                        let subject_name = subject_name.build();
                                        identity_csr.set_subject_name(&subject_name).map_err(
                                            |err| {
                                                Error::Internal(InternalError::CreateCert(
                                                    Box::new(err),
                                                ))
                                            },
                                        )?;

                                        let mut extensions =
                                            openssl::stack::Stack::new().map_err(|err| {
                                                Error::Internal(InternalError::CreateCert(
                                                    Box::new(err),
                                                ))
                                            })?;
                                        let client_extension =
                                            openssl::x509::extension::ExtendedKeyUsage::new()
                                                .client_auth()
                                                .build()
                                                .map_err(|err| {
                                                    Error::Internal(InternalError::CreateCert(
                                                        Box::new(err),
                                                    ))
                                                })?;
                                        extensions.push(client_extension).map_err(|err| {
                                            Error::Internal(InternalError::CreateCert(Box::new(
                                                err,
                                            )))
                                        })?;
                                        identity_csr.add_extensions(&extensions).map_err(
                                            |err| {
                                                Error::Internal(InternalError::CreateCert(
                                                    Box::new(err),
                                                ))
                                            },
                                        )?;

                                        identity_csr.set_pubkey(&identity_public_key).map_err(
                                            |err| {
                                                Error::Internal(InternalError::CreateCert(
                                                    Box::new(err),
                                                ))
                                            },
                                        )?;

                                        identity_csr
                                            .sign(
                                                &identity_private_key,
                                                openssl::hash::MessageDigest::sha256(),
                                            )
                                            .map_err(|err| {
                                                Error::Internal(InternalError::CreateCert(
                                                    Box::new(err),
                                                ))
                                            })?;

                                        let identity_csr = identity_csr.build();
                                        let identity_csr =
                                            identity_csr.to_pem().map_err(|err| {
                                                Error::Internal(InternalError::CreateCert(
                                                    Box::new(err),
                                                ))
                                            })?;

                                        // Request the new EST identity cert using the EST bootstrap identity cert.

                                        let bootstrap_identity_private_key =
                                            CString::new(
                                                bootstrap_identity_private_key.0.clone(),
                                            )
                                            .map_err(
                                                |err| {
                                                    Error::Internal(InternalError::CreateCert(
                                                        Box::new(err),
                                                    ))
                                                },
                                            )?;
                                        let bootstrap_identity_private_key = api
                                            .key_engine
                                            .load_private_key(&bootstrap_identity_private_key)
                                            .map_err(|err| {
                                                Error::Internal(InternalError::CreateCert(
                                                    Box::new(err),
                                                ))
                                            })?;

                                        let x509 = est::create_cert(
                                            identity_csr,
                                            url,
                                            &headers,
                                            auth_basic,
                                            Some((
                                                &bootstrap_identity_cert,
                                                &bootstrap_identity_private_key,
                                            )),
                                            trusted_certs_x509,
                                            api.proxy_uri.clone(),
                                        )
                                        .await?;

                                        let path = aziot_certd_config::util::get_path(
                                            &api.homedir_path,
                                            &api.preloaded_certs,
                                            identity_cert,
                                            true,
                                        )
                                        .map_err(|err| {
                                            Error::Internal(InternalError::GetPath(err))
                                        })?;
                                        write(path, &x509).map_err(|err| {
                                            Error::Internal(InternalError::CreateCert(Box::new(
                                                err,
                                            )))
                                        })?;

                                        // EST identity cert was obtained and persisted successfully. Now recurse to retry the original cert request.

                                        let x509 = create_cert(api, id, csr, issuer.clone()).await?;
                                        Ok(x509)
                                    }

                                    Err(bootstrap_identity_err) => {
                                        // Neither EST identity cert nor EST bootstrap identity cert could be obtained.
                                        Err(Error::Internal(InternalError::CreateCert(format!(
                                            "cert {:?} is configured to be issued by EST, but neither EST identity nor EST bootstrap identity could be obtained; \
                                            {} {}",
                                            id,
                                            identity_err,
                                            bootstrap_identity_err,
                                        ).into())))
                                    }
                                }
                            }
                        }
                    }
                    else {
                        // We need to only use basic auth with the EST server.

                        let x509 = est::create_cert(
                            csr.to_owned(),
                            url,
                            &headers,
                            auth_basic,
                            None,
                            trusted_certs_x509,
                            api.proxy_uri.clone(),
                        )
                        .await?;

                        let path = aziot_certd_config::util::get_path(
                            &api.homedir_path,
                            &api.preloaded_certs,
                            &id,
                            true,
                        )
                        .map_err(|err| Error::Internal(InternalError::GetPath(err)))?;
                        write(path, &x509).map_err(|err| {
                            Error::Internal(InternalError::CreateCert(Box::new(err)))
                        })?;

                        Ok(x509)
                    }
                }

                CertIssuanceMethod::LocalCa => {
                    // Indirect reference to the local CA. Look it up.

                    let (issuer_cert, issuer_private_key) = match &api.cert_issuance.local_ca {
                        Some(CertAuthority { cert, pk }) => {
                            let private_key =
                                api.key_client.load_key_pair(pk).map_err(|err| {
                                    Error::Internal(InternalError::CreateCert(Box::new(err)))
                                })?;
                            (cert.clone(), private_key)
                        }

                        None => {
                            return Err(Error::Internal(InternalError::CreateCert(
                                format!(
                                    "cert {:?} is configured to be issued by local CA, but local CA is not configured",
                                    id,
                                )
                                .into(),
                            )))
                        }
                    };

                    // Recurse with the local CA set explicitly as the issuer parameter.

                    let x509 = create_cert(api, id, csr, Some((issuer_cert, issuer_private_key)))
                        .await?;
                    Ok(x509)
                }

                CertIssuanceMethod::SelfSigned => {
                    // Since the client did not give us their private key handle, we assume that the key is named the same as the cert.
                    //
                    // TODO: Is there a way to not have to assume this?
                    let key_pair_handle = api
                        .key_client
                        .load_key_pair(&id)
                        .map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

                    // Recurse with explicit issuer.
                    let x509 = create_cert(api, id.clone(), csr, Some((id, key_pair_handle))).await?;
                    Ok(x509)
                }
            }
        }
    }

    Box::pin(create_cert_inner(api, id, csr, issuer))
}

fn get_cert_inner(
    homedir_path: &std::path::Path,
    preloaded_certs: &BTreeMap<String, PreloadedCert>,
    id: &str,
) -> Result<Option<Vec<u8>>, Error> {
    match preloaded_certs.get(id) {
        Some(PreloadedCert::Uri(_)) | None => {
            let path = aziot_certd_config::util::get_path(homedir_path, preloaded_certs, id, true)
                .map_err(|err| Error::Internal(InternalError::GetPath(err)))?;
            let bytes = load_inner(&path)?;
            Ok(bytes)
        }

        Some(PreloadedCert::Ids(ids)) => {
            let mut result = vec![];
            for id in ids {
                if let Some(bytes) = get_cert_inner(homedir_path, preloaded_certs, id)? {
                    result.extend_from_slice(&bytes);
                }
            }
            Ok((!result.is_empty()).then(|| result))
        }
    }
}

fn principal_to_map(
    principal: Vec<Principal>,
) -> BTreeMap<libc::uid_t, Vec<wildmatch::WildMatch>> {
    let mut result: BTreeMap<_, Vec<_>> = Default::default();

    for Principal { uid, certs } in principal {
        result.entry(uid).or_default().extend(
            certs
                .into_iter()
                .map(|cert| wildmatch::WildMatch::new(&cert)),
        );
    }

    result
}
