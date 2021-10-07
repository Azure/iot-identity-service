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
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use aziot_certd_config::{
    CertIssuance, CertIssuanceMethod, CertIssuanceOptions, CertSubject, Config, Endpoints,
    EstAuth, EstAuthX509, CertAuthority, PreloadedCert, Principal,
};
use aziot_key_common::KeyHandle;
use config_common::watcher::UpdateConfig;
use http_common::{Connector, get_proxy_uri};

use futures_util::lock::Mutex;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Public};
use openssl::stack::Stack;
use openssl::x509::{X509, X509Name, X509Req, extension};
use openssl2::FunctionalEngine;
use url::Url;

type BoxedError = Box<dyn StdError + Send + Sync>;

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
    key_engine: FunctionalEngine,
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

        let x509 = create_cert_inner(
                &mut *this,
                id,
                csr,
                issuer
            )
            .await
            .map_err(|err| Error::Internal(InternalError::CreateCert(err)))?;

        Ok(x509)
    }

    pub fn import_cert(&mut self, id: &str, pem: &[u8], user: libc::uid_t) -> Result<(), Error> {
        if !self.authorize(user, id) {
            return Err(Error::Unauthorized(user, id.to_string()));
        }

        import_cert_inner(
                &self.homedir_path,
                &self.preloaded_certs,
                id,
                pem
            )
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

fn build_name(subj: &CertSubject) -> Result<X509Name, Error> {
    let mut builder = X509Name::builder()
        .map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

    match subj {
        CertSubject::CommonName(cn) =>
            builder
                .append_entry_by_text("CN", &cn)
                .map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?,
        CertSubject::Subject(fields) =>
            for (name, value) in fields {
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

fn create_with_issuer(
    key_engine: &mut FunctionalEngine,
    homedir_path: &Path,
    preloaded_certs: &BTreeMap<String, PreloadedCert>,
    id: &str,
    csr: &[u8],
    cert_options: Option<&CertIssuanceOptions>,
    issuer: &(String, KeyHandle)
) -> Result<Vec<u8>, BoxedError> {
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
        .map_err(|err| Error::invalid_parameter("issuer.privateKeyHandle", err))?;
    let issuer_privkey = key_engine
        .load_private_key(&issuer_privkey)?;

    let mut builder = X509::builder()?;
    builder.set_version(2)?;
    builder.set_subject_name(subject_name)?;
    builder.set_pubkey(&pubkey)?;
    builder.set_not_before(&*Asn1Time::days_from_now(0)?)?;

    let _: Option<_> = req.extensions()
        .map(|exts| -> Result<_, BoxedError> {
            for ext in exts {
                builder.append_extension(ext)?
            }
            Ok(())
        })
        .ok()
        .transpose()?;

    let issuer_x509_stack: Vec<X509>;
    let (issuer_name, min_expiry, issuer_pem) = if &id != &issuer.0 {
        let issuer_x509_pem = get_cert_inner(
                homedir_path,
                preloaded_certs,
                &issuer.0
            )?
            .ok_or_else(|| Error::invalid_parameter("issuer.certId", "not found"))?;
        issuer_x509_stack = X509::stack_from_pem(&issuer_x509_pem)?;

        let issuer_x509 = issuer_x509_stack.get(0)
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

    if let Some(ref pem) = issuer_pem {
        x509.extend_from_slice(pem)
    }

    Ok(x509)
}

async fn create_with_identity(
    key_engine: &mut FunctionalEngine,
    key_client: &aziot_key_client::Client,
    homedir_path: &Path,
    preloaded_certs: &BTreeMap<String, PreloadedCert>,
    proxy_uri: Option<hyper::Uri>,
    csr: &[u8],
    auth: &EstAuth,
    url: &Url,
    trusted_certs: &[X509]
) -> Result<Vec<u8>, BoxedError> {
    let id_opt = auth.x509.as_ref()
        .map(|x509| &x509.identity)
        .map(|CertAuthority { cert, pk }| -> Result<_, BoxedError> {
            let cert = get_cert_inner(homedir_path, preloaded_certs, &cert)?
                .ok_or_else(||
                    format!(
                        "could not get EST identity cert: {}",
                        io::Error::from(io::ErrorKind::NotFound)
                    )
                )?;
            let handle = key_client.load_key_pair(&pk)
                .and_then(|handle| Ok(CString::new(handle.0)?))
                .map_err(|err|
                    format!(
                        "could not get EST identity cert private key: {}",
                        err
                    )
                )?;

            let pk = key_engine.load_private_key(&handle)?;

            Ok((cert, pk))
        })
        .transpose()?;

    Ok(
        est::create_cert(
                csr.to_owned(),
                url,
                auth.headers.as_ref(),
                auth.basic.as_ref(),
                id_opt.as_ref(),
                trusted_certs,
                proxy_uri
            )
            .await?
    )
}


async fn create_cert_inner(
    api: &mut Api,
    id: String,
    csr: Vec<u8>,
    issuer: Option<(String, KeyHandle)>
) -> Result<Vec<u8>, BoxedError> {
    // Hints for borrow checker
    let cert_issuance = &api.cert_issuance;
    let homedir_path = &api.homedir_path;
    let preloaded_certs = &api.preloaded_certs;
    let key_client = &api.key_client;
    let key_engine = &mut api.key_engine;
    let proxy_uri = &api.proxy_uri;

    let cert_options = cert_issuance.certs.get(&id);

    let x509 = if let Some(ref issuer) = issuer {
        create_with_issuer(
            key_engine,
            homedir_path,
            preloaded_certs,
            &id,
            &csr,
            cert_options,
            issuer
        )?
    }
    else {
        let cert_options = cert_options
            .ok_or_else(||
                Error::invalid_parameter(
                    "issuer",
                    "issuer is required for locally-issued certs"
                )
            )?;

        match &cert_options.method {
            CertIssuanceMethod::SelfSigned => {
                let issuer_id = id.clone();
                let pk = key_client.load_key_pair(&id)?;

                create_with_issuer(
                    key_engine,
                    homedir_path,
                    preloaded_certs,
                    &id,
                    &csr,
                    Some(cert_options),
                    &(issuer_id, pk)
                )?
            },
            CertIssuanceMethod::LocalCa => {
                let CertAuthority { cert, pk } = cert_issuance.local_ca.as_ref()
                    .ok_or_else(||
                        format!(
                            "cert {:?} is configured to be issued by local CA, but local CA is not configured",
                            id
                        )
                    )?;

                let issuer_id = cert.clone();
                let pk = key_client.load_key_pair(&pk)?;

                create_with_issuer(
                    key_engine,
                    homedir_path,
                    preloaded_certs,
                    &id,
                    &csr,
                    Some(cert_options),
                    &(issuer_id, pk)
                )?
            },
            CertIssuanceMethod::Est { url, auth } => {
                let default = cert_issuance.est.as_ref();

                let auth = auth.as_ref()
                    .or_else(|| default.map(|default| &default.auth))
                    .ok_or_else(||
                        format!(
                            "cert {:?} is configured to be issued by EST, but EST auth is not configured",
                            id
                        )
                    )?;

                let url = url.as_ref()
                    .or_else(||
                        default
                            .map(|default| &default.urls)
                            .and_then(|urls|
                                urls.get(&id)
                                    .or_else(|| urls.get("default"))
                            )
                    )
                    .ok_or_else(||
                        format!(
                            "cert {:?} is configured to be issued by EST, but EST URL is not configured",
                            id
                        )
                    )?;

                let trusted_certs = default
                    .map(|default|
                        default.trusted_certs
                            .iter()
                            .try_fold(Vec::new(), |mut acc, cert| {
                                let pem = get_cert_inner(
                                        homedir_path,
                                        preloaded_certs,
                                        cert
                                    )?
                                    .ok_or_else(||
                                        format!(
                                            "cert_issuance.est.trusted_certs contains unreadable cert {:?}",
                                            cert
                                        )
                                    )?;

                                acc.extend(X509::stack_from_pem(&pem)?);
                                Result::<_, BoxedError>::Ok(acc)
                            })
                    )
                    .transpose()?
                    .unwrap_or_default();

                let first_try = create_with_identity(
                        key_engine,
                        key_client,
                        homedir_path,
                        preloaded_certs,
                        proxy_uri.clone(),
                        &csr,
                        auth,
                        url,
                        &trusted_certs
                    )
                    .await;

                match first_try {
                    Ok(x509) => x509,
                    Err(err) => {
                        let auth_x509 = auth.x509.as_ref()
                            .ok_or_else(||
                                format!(
                                    "cert {:?} is configured to be issued by EST,\
                                    but EST identity could not be obtained\
                                    and EST X509 authentication with bootstrapping is not in use: {}",
                                    id, err
                                )
                            )?;

                        let CertAuthority { cert: bcert_path, pk: bpk_path } = auth_x509.bootstrap_identity.as_ref()
                            .ok_or_else(||
                                format!(
                                    "cert {:?} is configured to be issued by EST,\
                                    but EST identity could not be obtained\
                                    and EST bootstrap identity is not configured: {}",
                                    id, err
                                )
                            )?;

                        let bcert = get_cert_inner(
                                homedir_path,
                                preloaded_certs,
                                &bcert_path
                            )?
                            .ok_or_else(||
                                format!(
                                    "could not get EST bootstrap identity cert: {}",
                                    io::Error::from(io::ErrorKind::NotFound)
                                )
                            )?;
                        let bpk = key_client.load_key_pair(&bpk_path)
                            .map_err(|err|
                                format!(
                                    "could not get EST bootstrap identity cert private key: {}",
                                    err
                                )
                            )?;

                        if let Ok(ref handle) = key_client.load_key_pair(&auth_x509.identity.pk) {
                            key_client.delete_key_pair(handle)?;
                        }

                        let handle = key_client.create_key_pair_if_not_exists(
                                &auth_x509.identity.pk,
                                Some("ec-p256:rsa-4096:*")
                            )
                            .and_then(|handle| Ok(CString::new(handle.0)?))?;

                        let pubkey = key_engine.load_public_key(&handle)?;
                        let privkey = key_engine.load_private_key(&handle)?;

                        let subject_name = build_name(
                                cert_options.subject.as_ref()
                                    .unwrap_or(&CertSubject::CommonName("est-id".to_owned()))
                            )?;

                        let mut builder = X509Req::builder()?;
                        builder.set_version(0)?;
                        builder.set_subject_name(&subject_name)?;

                        let mut exts = Stack::new()?;
                        exts.push(
                                extension::ExtendedKeyUsage::new()
                                    .client_auth()
                                    .build()?
                            )?;

                        builder.add_extensions(&exts)?;
                        builder.set_pubkey(&pubkey)?;
                        builder.sign(&privkey, MessageDigest::sha256())?;

                        let csr = builder.build();

                        vec![]
                    }
                }
            }
        }
    };

    import_cert_inner(
        homedir_path,
        preloaded_certs,
        &id,
        &x509
    )?;

    Ok(x509)
}

fn load_inner(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    match read(path) {
        Ok(cert_bytes) => Ok(Some(cert_bytes)),
        Err(ref err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::Internal(InternalError::ReadFile(err))),
    }
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

fn get_cert_dummy(
    api: &Api,
    id: &str,
) -> Result<Option<Vec<u8>>, Error> {
    match api.preloaded_certs.get(id) {
        Some(PreloadedCert::Uri(_)) | None => {
            let path = aziot_certd_config::util::get_path(&api.homedir_path, &api.preloaded_certs, id, true)
                .map_err(|err| Error::Internal(InternalError::GetPath(err)))?;
            let bytes = load_inner(&path)?;
            Ok(bytes)
        }

        Some(PreloadedCert::Ids(ids)) => {
            let mut result = vec![];
            for ref id in ids {
                if let Some(bytes) = get_cert_dummy(api, id)? {
                    result.extend_from_slice(&bytes);
                }
            }
            Ok((!result.is_empty()).then(|| result))
        }
    }
}

fn import_cert_inner(
    homedir_path: &Path,
    preloaded_certs: &BTreeMap<String, PreloadedCert>,
    id: &str,
    x509: &[u8]
) -> Result<(), Error> {
    let path = aziot_certd_config::util::get_path(
            homedir_path,
            preloaded_certs,
            id,
            true
        )
        .map_err(|err| Error::Internal(InternalError::GetPath(err)))?;

    write(&path, x509)
        .map_err(|err| Error::Internal(InternalError::WriteFile(err)))?;

    Ok(())
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
