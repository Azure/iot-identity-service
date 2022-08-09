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
mod renewal;

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_recursion::async_recursion;
use async_trait::async_trait;
use futures_util::lock::Mutex;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use openssl::stack::Stack;
use openssl::x509::{extension, X509Name, X509NameRef, X509Req, X509ReqRef, X509};
use openssl2::FunctionalEngine;

use aziot_certd_config::{
    CertIssuance, CertIssuanceMethod, CertificateWithPrivateKey, Config, Endpoints, EstAuth,
    EstAuthBasic, PreloadedCert, Principal,
};
use config_common::watcher::UpdateConfig;
use http_common::Connector;

use error::{Error, InternalError};

pub(crate) type BoxedError = Box<dyn StdError + Send + Sync>;

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

    let renewal_engine = cert_renewal::engine::new();

    let est_config = est::EstConfig::new(&cert_issuance, &homedir_path, &preloaded_certs)?;

    let api = {
        let key_client_async = Arc::new(aziot_key_client_async::Client::new(
            aziot_key_common_http::ApiVersion::V2021_05_01,
            key_connector.clone(),
            0,
        ));

        let key_client = Arc::new(aziot_key_client::Client::new(
            aziot_key_common_http::ApiVersion::V2021_05_01,
            key_connector,
        ));

        let key_engine = aziot_key_openssl_engine::load(key_client)
            .map_err(|err| Error::Internal(InternalError::LoadKeyOpensslEngine(err)))?;

        let key_engine = Arc::new(std::sync::Mutex::new(key_engine));

        let est_config = Arc::new(tokio::sync::RwLock::new(est_config));

        Api {
            homedir_path,
            cert_issuance,
            preloaded_certs,
            principals: principal_to_map(principal),
            renewal_engine,

            key_client: key_client_async,
            key_engine,
            est_config,
        }
    };

    api.init_est_id_renewal().await?;

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
    renewal_engine: Arc<Mutex<cert_renewal::RenewalEngine<renewal::EstIdRenewal>>>,

    key_client: Arc<aziot_key_client_async::Client>,
    key_engine: Arc<std::sync::Mutex<FunctionalEngine>>,

    est_config: Arc<tokio::sync::RwLock<est::EstConfig>>,
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

        let req = X509Req::from_pem(&csr).map_err(|err| Error::invalid_parameter("csr", err))?;
        let pubkey = req
            .public_key()
            .map_err(|err| Error::invalid_parameter("csr", err))?;

        if !req
            .verify(&pubkey)
            .map_err(|err| Error::invalid_parameter("csr", err))?
        {
            return Err(Error::invalid_parameter(
                "csr",
                "CSR failed to be verified with its public key".to_owned(),
            ));
        }

        let issuer = issuer
            .map(|(id, handle)| -> Result<_, Error> {
                let pem = get_cert_inner(&this.homedir_path, &this.preloaded_certs, &id)
                    .map_err(|err| Error::Internal(InternalError::CreateCert(err.into())))?
                    .ok_or_else(|| Error::invalid_parameter("issuer.certId", "not found"))?;
                let stack = X509::stack_from_pem(&pem)
                    .map_err(|err| Error::Internal(InternalError::CreateCert(err.into())))?;
                if stack.is_empty() {
                    return Err(Error::invalid_parameter("issuer.certId", "invalid issuer"));
                }

                let handle = CString::new(handle.0)
                    .map_err(|err| Error::invalid_parameter("issuer.privateKeyHandle", err))?;

                Ok((stack, handle))
            })
            .transpose()?;

        let x509 = create_cert_inner(
            &mut *this,
            &id,
            (&req, &pubkey),
            issuer.as_ref().map(|(x509, pk)| (&**x509, &**pk)),
        )
        .await
        .map_err(|err| Error::Internal(InternalError::CreateCert(err)))?;

        write_cert(&this.homedir_path, &this.preloaded_certs, &id, &x509)?;

        Ok(x509)
    }

    pub fn import_cert(&mut self, id: &str, pem: &[u8], user: libc::uid_t) -> Result<(), Error> {
        if !self.authorize(user, id) {
            return Err(Error::Unauthorized(user, id.to_string()));
        }

        write_cert(&self.homedir_path, &self.preloaded_certs, id, pem)
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
        match fs::remove_file(path) {
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
            return certs.iter().any(|cert| cert.matches(id));
        }

        false
    }

    async fn init_est_id_renewal(&self) -> Result<(), Error> {
        // Get a list of existing EST ID certs to renew. Use a BTreeMap to remove duplicates.
        let mut est_credentials = BTreeMap::new();

        // Add the default EST ID cert.
        if let Some(est) = &self.cert_issuance.est {
            if let Some(auth) = &est.auth {
                if let Some(x509) = &auth.x509 {
                    if let Ok(cert) = get_cert_inner(
                        &self.homedir_path,
                        &self.preloaded_certs,
                        &x509.identity.cert,
                    ) {
                        if cert.is_some() {
                            est_credentials.insert(x509.identity.clone(), &x509.identity.cert);
                        }
                    }
                }
            }
        }

        // Add EST ID certs for individual issuance options.
        for (cert_id, options) in &self.cert_issuance.certs {
            if let CertIssuanceMethod::Est {
                auth: Some(auth), ..
            } = &options.method
            {
                if let Some(x509) = &auth.x509 {
                    if let Ok(cert) = get_cert_inner(
                        &self.homedir_path,
                        &self.preloaded_certs,
                        &x509.identity.cert,
                    ) {
                        if cert.is_some() {
                            est_credentials.insert(x509.identity.clone(), cert_id);
                        }
                    }
                }
            }
        }

        // Add existing EST credentials to auto-renewal. Credentials specified in the config that do not
        // exist yet will be added when they are created.
        let policy = {
            let est_config = self.est_config.read().await;

            est_config.renewal.policy.clone()
        };

        for (credential, cert_id) in est_credentials {
            let interface = renewal::EstIdRenewal::new(cert_id, credential.clone(), self).await?;

            cert_renewal::engine::add_credential(
                &self.renewal_engine,
                &credential.cert,
                &credential.pk,
                policy.clone(),
                interface,
            )
            .await
            .map_err(|err| Error::Internal(InternalError::CreateCert(err.into())))?;
        }

        Ok(())
    }
}

#[async_trait]
impl UpdateConfig for Api {
    type Config = Config;
    type Error = Error;

    async fn update_config(&mut self, new_config: Self::Config) -> Result<(), Self::Error> {
        log::info!("Detected change in config files. Updating config.");

        // Don't allow changes to homedir path or endpoints while daemon is running.
        // Only update other fields.
        let Config {
            cert_issuance,
            preloaded_certs,
            principal,
            homedir_path: _,
            endpoints: _,
        } = new_config;

        // Config change may have altered cert issuance. Reset the auto-renewed EST ID certs.
        cert_renewal::engine::clear(&self.renewal_engine).await;
        let new_est_config =
            est::EstConfig::new(&cert_issuance, &self.homedir_path, &preloaded_certs)?;

        {
            let mut est_config = self.est_config.write().await;

            *est_config = new_est_config;
        }

        self.cert_issuance = cert_issuance;
        self.preloaded_certs = preloaded_certs;
        self.principals = principal_to_map(principal);

        self.init_est_id_renewal().await?;

        log::info!("Config update finished.");
        Ok(())
    }
}

#[async_recursion]
async fn create_cert_inner<'a>(
    api: &'a mut Api,
    id: &'a str,
    (req, pubkey): (&'a X509ReqRef, &'a PKeyRef<Public>),
    issuer: Option<(&'a [X509], &'a CStr)>,
) -> Result<Vec<u8>, BoxedError> {
    let cert_options = api.cert_issuance.certs.get(id);

    if let Some((stack, issuer_handle)) = issuer {
        let expiry = &*Asn1Time::days_from_now(
            cert_options.and_then(|opts| opts.expiry_days).unwrap_or(30),
        )?;
        let name_override = cert_options
            .and_then(|opts| opts.subject.as_ref())
            .map(X509Name::try_from)
            .transpose()?;

        let subject_name = name_override
            .as_deref()
            .unwrap_or_else(|| req.subject_name());

        let issuer_pk = {
            let mut key_engine = api.key_engine.lock().expect("mutex poisoned");

            key_engine.load_private_key(issuer_handle)?
        };

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(subject_name)?;
        builder.set_pubkey(pubkey)?;
        builder.set_not_before(&*Asn1Time::days_from_now(0)?)?;

        let (mut has_skid, mut has_akid) = (false, false);

        // x509_req.extensions() returns an Err variant if no extensions are
        // present in the req. Ignore this Err and only copy extensions if
        // provided in the req.
        if let Ok(exts) = req.extensions() {
            for ext in exts {
                let (name, _) = openssl2::extension::parse(&ext);

                if name == openssl::nid::Nid::SUBJECT_KEY_IDENTIFIER {
                    has_skid = true;
                } else if name == openssl::nid::Nid::AUTHORITY_KEY_IDENTIFIER {
                    has_akid = true;
                }

                builder.append_extension(ext)?;
            }
        }

        let (subject_name, expiry, issuer_ref) =
            stack.get(0).map_or((subject_name, expiry, None), |x509| {
                let issuer_expiry = x509.not_after();

                (
                    x509.subject_name(),
                    if expiry < issuer_expiry {
                        expiry
                    } else {
                        issuer_expiry
                    },
                    Some(x509.as_ref()),
                )
            });

        if !has_skid {
            let subj_key_id = openssl::x509::extension::SubjectKeyIdentifier::new();
            let context = builder.x509v3_context(issuer_ref, None);
            let subj_key_id = subj_key_id.build(&context)?;
            builder.append_extension(subj_key_id)?;
        }

        if issuer_ref.is_some() && !has_akid {
            let mut auth_key_id = openssl::x509::extension::AuthorityKeyIdentifier::new();
            auth_key_id.keyid(true);

            let context = builder.x509v3_context(issuer_ref, None);

            // OpenSSL fails if the issuer does not contain an SKID. If this happens,
            // skip the AKID extension and continue.
            if let Ok(auth_key_id) = auth_key_id.build(&context) {
                builder.append_extension(auth_key_id)?;
            }
        }

        builder.set_not_after(expiry)?;
        builder.set_issuer_name(subject_name)?;
        builder.sign(&issuer_pk, MessageDigest::sha256())?;

        let mut pem = builder.build().to_pem()?;

        for x509 in stack {
            pem.extend_from_slice(&x509.to_pem()?);
        }

        Ok(pem)
    } else {
        let cert_options = cert_options.ok_or_else(|| {
            Error::invalid_parameter("issuer", "issuer is required for locally-issued certs")
        })?;

        match &cert_options.method {
            CertIssuanceMethod::SelfSigned => {
                let pk = api.key_client.load_key_pair(id).await?;

                create_cert_inner(api, id, (req, pubkey), Some((&[], &CString::new(pk.0)?))).await
            }
            CertIssuanceMethod::LocalCa => {
                let CertificateWithPrivateKey { cert, pk } = api.cert_issuance.local_ca.as_ref()
                    .ok_or_else(||
                        format!(
                            "cert {:?} is configured to be issued by local CA, but local CA is not configured",
                            id
                        )
                    )?;

                let pem = get_cert_inner(&api.homedir_path, &api.preloaded_certs, cert)?
                    .ok_or_else(|| format!("cert for issuer id {:?} not found", id))?;
                let stack = X509::stack_from_pem(&pem)?;

                let pk = api.key_client.load_key_pair(pk).await?;

                create_cert_inner(api, id, (req, pubkey), Some((&stack, &CString::new(pk.0)?)))
                    .await
            }
            CertIssuanceMethod::Est { url, auth } => {
                let (auth, url) = get_est_opts(id, api, Some((url.as_ref(), auth.as_ref())))?;

                // Get the EST identity cert if configured. If it does not exist, create it.
                let client_credentials = if let Some(x509) = &auth.x509 {
                    if let Ok((id_cert_chain, id_pk)) = cert_renewal::engine::get_credential(
                        &api.renewal_engine,
                        &x509.identity.cert,
                        &x509.identity.pk,
                    )
                    .await
                    {
                        let mut id_cert = Vec::new();

                        for cert in id_cert_chain {
                            let mut cert = cert.to_pem()?;

                            id_cert.append(&mut cert);
                        }

                        Some((id_cert, id_pk))
                    } else {
                        let subject_name = if let Some(subject) = &cert_options.subject {
                            X509Name::try_from(subject)?
                        } else {
                            // X509NameRef to X509Name.
                            let subject = req.subject_name().to_der()?;

                            X509Name::from_der(&subject)?
                        };

                        let bootstrap_auth = x509.bootstrap_identity.as_ref().ok_or_else(|| {
                            format!(
                                "cert {:?} is configured to be issued by EST, \
                                    but EST identity could not be obtained \
                                    and EST bootstrap identity is not configured",
                                id
                            )
                        })?;

                        let bootstrap_credentials = get_credentials(bootstrap_auth, api).await?;

                        if let Ok(ref handle) =
                            api.key_client.load_key_pair(&x509.identity.pk).await
                        {
                            api.key_client.delete_key_pair(handle).await?;
                        }

                        let est_id_keys = {
                            let handle = api
                                .key_client
                                .create_key_pair_if_not_exists(
                                    &x509.identity.pk,
                                    Some("ec-p256:rsa-4096:*"),
                                )
                                .await?;
                            let cstr = CString::new(handle.0)?;

                            let mut key_engine = api.key_engine.lock().expect("mutex poisoned");

                            let id_pubkey = key_engine.load_public_key(&cstr)?;
                            let id_pk = key_engine.load_private_key(&cstr)?;

                            (id_pk, id_pubkey)
                        };

                        // Request the new EST identity cert using the EST bootstrap identity cert.
                        let (est_id, est_id_key, renewal_policy) = {
                            let est_id_key = est_id_keys.0.clone();
                            let est_config = api.est_config.read().await;

                            let est_id = create_est_id(
                                &subject_name,
                                est_id_keys,
                                &url,
                                bootstrap_credentials,
                                auth.basic.as_ref(),
                                &est_config.trusted_certs,
                                est_config.proxy_uri.clone(),
                            )
                            .await
                            .map_err(|err| {
                                format!(
                                    "cert {:?} is configured to be issued by EST, \
                                        but neither EST identity nor EST bootstrap \
                                        identity could be obtained: {}",
                                    id, err
                                )
                            })?;

                            (est_id, est_id_key, est_config.renewal.policy.clone())
                        };

                        // Write the new EST ID cert and add it to cert renewal.
                        write_cert(
                            &api.homedir_path,
                            &api.preloaded_certs,
                            &x509.identity.cert,
                            &est_id,
                        )?;

                        let interface =
                            renewal::EstIdRenewal::new(id, x509.identity.clone(), api).await?;

                        if let Err(err) = cert_renewal::engine::add_credential(
                            &api.renewal_engine,
                            &x509.identity.cert,
                            &x509.identity.pk,
                            renewal_policy,
                            interface,
                        )
                        .await
                        {
                            log::warn!(
                                "Failed to add {} to cert auto-renewal: {}",
                                x509.identity.cert,
                                err
                            );
                        }

                        Some((est_id, est_id_key))
                    }
                } else {
                    None
                };

                let est_config = api.est_config.read().await;

                est::create_cert(
                    chunked_base64_encode(&req.to_der()?),
                    &url,
                    auth.basic.as_ref(),
                    client_credentials
                        .as_ref()
                        .map(|(cert, pk)| (&**cert, &**pk)),
                    &est_config.trusted_certs,
                    est_config.proxy_uri.clone(),
                )
                .await
            }
        }
    }
}

pub(crate) fn get_est_opts(
    cert_id: &str,
    api: &Api,
    opts: Option<(Option<&url::Url>, Option<&EstAuth>)>,
) -> Result<(EstAuth, url::Url), BoxedError> {
    // Use parameters if provided. Otherwise, look up from cert issuance options.
    // Use defaults if not found in cert issuance options.
    let (url, auth) = if let Some((url, auth)) = opts {
        (url, auth)
    } else if let Some(cert_options) = api.cert_issuance.certs.get(cert_id) {
        if let CertIssuanceMethod::Est { url, auth } = &cert_options.method {
            (url.as_ref(), auth.as_ref())
        } else {
            return Err(format!("cert {:?} does not have EST issuance method", cert_id).into());
        }
    } else {
        (None, None)
    };

    let default = api.cert_issuance.est.as_ref();

    let auth = auth
        .or({
            if let Some(default) = default {
                default.auth.as_ref()
            } else {
                None
            }
        })
        .ok_or_else(|| {
            format!(
                "cert {:?} is configured to be issued by EST, but EST auth is not configured",
                cert_id
            )
        })?;

    let url = url
        .or_else(|| {
            default
                .map(|default| &default.urls)
                .and_then(|urls| urls.get(cert_id).or_else(|| urls.get("default")))
        })
        .ok_or_else(|| {
            format!(
                "cert {:?} is configured to be issued by EST, but EST URL is not configured",
                cert_id
            )
        })?;

    Ok((auth.clone(), url.clone()))
}

async fn get_credentials(
    credential: &CertificateWithPrivateKey,
    api: &mut Api,
) -> Result<(Vec<u8>, PKey<Private>), BoxedError> {
    let cert = get_cert_inner(&api.homedir_path, &api.preloaded_certs, &credential.cert)?
        .ok_or_else(|| {
            format!(
                "could not get EST bootstrap identity cert: {}",
                io::Error::from(io::ErrorKind::NotFound)
            )
        })?;

    let pk_handle = api.key_client.load_key_pair(&credential.pk).await?;

    let pk_handle = CString::new(pk_handle.0)?;

    let mut key_engine = api.key_engine.lock().expect("mutex poisoned");

    let pk = key_engine.load_private_key(&pk_handle).map_err(|err| {
        format!(
            "could not get EST bootstrap identity cert private key: {}",
            err
        )
    })?;

    Ok((cert, pk))
}

pub(crate) async fn create_est_id(
    subject_name: &X509NameRef,
    keys: (PKey<Private>, PKey<Public>),
    url: &url::Url,
    x509_auth: (Vec<u8>, PKey<Private>),
    basic_auth: Option<&EstAuthBasic>,
    trusted_certs: &[X509],
    proxy_uri: Option<hyper::Uri>,
) -> Result<Vec<u8>, BoxedError> {
    let mut builder = X509Req::builder()?;
    builder.set_version(0)?;
    builder.set_subject_name(subject_name)?;

    let mut exts = Stack::new()?;
    exts.push(extension::ExtendedKeyUsage::new().client_auth().build()?)?;

    builder.add_extensions(&exts)?;
    builder.set_pubkey(&keys.1)?;
    builder.sign(&keys.0, MessageDigest::sha256())?;

    est::create_cert(
        chunked_base64_encode(&builder.build().to_der()?),
        url,
        basic_auth,
        Some((&x509_auth.0, &x509_auth.1)),
        trusted_certs,
        proxy_uri,
    )
    .await
}

fn load_inner(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    match fs::read(path) {
        Ok(cert_bytes) => Ok(Some(cert_bytes)),
        Err(ref err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::Internal(InternalError::ReadFile(err))),
    }
}

pub(crate) fn get_cert_inner(
    homedir_path: &Path,
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

fn write_cert(
    homedir_path: &Path,
    preloaded_certs: &BTreeMap<String, PreloadedCert>,
    id: &str,
    x509: &[u8],
) -> Result<(), Error> {
    let path = aziot_certd_config::util::get_path(homedir_path, preloaded_certs, id, true)
        .map_err(|err| Error::Internal(InternalError::GetPath(err)))?;

    fs::write(&path, x509).map_err(|err| Error::Internal(InternalError::WriteFile(err)))?;

    Ok(())
}

fn principal_to_map(principal: Vec<Principal>) -> BTreeMap<libc::uid_t, Vec<wildmatch::WildMatch>> {
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

#[inline]
fn chunked_base64_encode(bytes: &[u8]) -> Vec<u8> {
    const PEM_LINE_LENGTH: usize = 64;

    base64::encode(bytes)
        .into_bytes()
        .chunks(PEM_LINE_LENGTH)
        .flat_map(|chunk| chunk.iter().chain(b"\n"))
        .copied()
        .collect()
}
