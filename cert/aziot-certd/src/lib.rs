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

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::ffi::{CStr, CString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_recursion::async_recursion;
use async_trait::async_trait;
use futures_util::future::OptionFuture;
use futures_util::lock::Mutex;
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKeyRef, Public};
use openssl::stack::Stack;
use openssl::x509::{extension, X509Name, X509Req, X509ReqRef, X509};
use openssl2::FunctionalEngine;

use aziot_certd_config::{
    CertIssuance, CertIssuanceMethod, CertSubject, CertificateWithPrivateKey, Config, Endpoints,
    EstAuthX509, PreloadedCert, Principal,
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

        let proxy_uri = http_common::get_proxy_uri(None)
            .map_err(|err| Error::Internal(InternalError::InvalidProxyUri(Box::new(err))))?;

        Api {
            homedir_path,
            cert_issuance,
            preloaded_certs,
            principals: principal_to_map(principal),

            key_client: key_client_async,
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

    key_client: Arc<aziot_key_client_async::Client>,
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
            homedir_path: _,
            endpoints: _,
        } = new_config;
        self.cert_issuance = cert_issuance;
        self.preloaded_certs = preloaded_certs;
        self.principals = principal_to_map(principal);

        log::info!("Config update finished.");
        Ok(())
    }
}

fn build_name(subj: &CertSubject) -> Result<X509Name, BoxedError> {
    let mut builder = X509Name::builder()
        .map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

    match subj {
        CertSubject::CommonName(cn) => builder.append_entry_by_text("CN", cn)?,
        CertSubject::Subject(fields) => {
            for (name, value) in fields {
                builder.append_entry_by_text(name, value)?;
            }
        }
    }

    Ok(builder.build())
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
            .map(build_name)
            .transpose()?;

        let subject_name = name_override
            .as_deref()
            .unwrap_or_else(|| req.subject_name());

        let issuer_pk = api.key_engine.load_private_key(issuer_handle)?;

        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        builder.set_subject_name(subject_name)?;
        builder.set_pubkey(pubkey)?;
        builder.set_not_before(&*Asn1Time::days_from_now(0)?)?;

        // x509_req.extensions() returns an Err variant if no extensions are
        // present in the req. Ignore this Err and only copy extensions if
        // provided in the req.
        if let Ok(exts) = req.extensions() {
            for ext in exts {
                builder.append_extension(ext)?;
            }
        }

        let (subject_name, expiry) = stack.get(0).map_or((subject_name, expiry), |x509| {
            let issuer_expiry = x509.not_after();

            (
                x509.subject_name(),
                if expiry < issuer_expiry {
                    expiry
                } else {
                    issuer_expiry
                },
            )
        });

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
                let default = api.cert_issuance.est.as_ref();

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
                                urls.get(id)
                                    .or_else(|| urls.get("default"))
                            )
                    )
                    .ok_or_else(||
                        format!(
                            "cert {:?} is configured to be issued by EST, but EST URL is not configured",
                            id
                        )
                    )?;

                let mut trusted_certs = vec![];

                if let Some(certs) = default.map(|default| &default.trusted_certs) {
                    for cert in certs {
                        let pem = get_cert_inner(&api.homedir_path, &api.preloaded_certs, cert)?
                            .ok_or_else(|| {
                                format!(
                                    "cert_issuance.est.trusted_certs contains unreadable cert {:?}",
                                    cert
                                )
                            })?;

                        trusted_certs.extend(X509::stack_from_pem(&pem)?);
                    }
                }

                let id_opt: OptionFuture<_> = auth
                    .x509
                    .as_ref()
                    .map({
                        let homedir_path = &api.homedir_path;
                        let preloaded_certs = &api.preloaded_certs;
                        let key_client = &api.key_client;
                        let key_engine = &mut api.key_engine;

                        move |EstAuthX509 {
                                  identity: CertificateWithPrivateKey { cert, pk },
                                  ..
                              }| async move {
                            let cert = get_cert_inner(homedir_path, preloaded_certs, cert)?
                                .ok_or_else(|| {
                                    format!(
                                        "could not get EST identity cert: {}",
                                        io::Error::from(io::ErrorKind::NotFound)
                                    )
                                })?;
                            let pk = key_client
                                .load_key_pair(pk)
                                .await
                                .map_err(BoxedError::from)
                                .and_then(|handle| Ok(CString::new(handle.0)?))
                                .and_then(|cstr| Ok(key_engine.load_private_key(&cstr)?))
                                .map_err(|err| {
                                    format!("could not get EST identity cert private key: {}", err)
                                })?;

                            Ok((cert, pk))
                        }
                    })
                    .into();

                let id_opt: Result<_, BoxedError> = id_opt.await.transpose();

                match id_opt {
                    Ok(id_opt) => {
                        est::create_cert(
                            chunked_base64_encode(&req.to_der()?),
                            url,
                            auth.basic.as_ref(),
                            id_opt.as_ref().map(|(cert, pk)| (&**cert, &**pk)),
                            &trusted_certs,
                            api.proxy_uri.clone(),
                        )
                        .await
                    }
                    Err(err) => {
                        let auth_x509 = auth.x509.as_ref()
                            .ok_or_else(||
                                format!(
                                    "cert {:?} is configured to be issued by EST, \
                                    but EST identity could not be obtained \
                                    and EST X509 authentication with bootstrapping is not in use: {}",
                                    id, err
                                )
                            )?;

                        let CertificateWithPrivateKey {
                            cert: bid_cert,
                            pk: bid_pk,
                        } = auth_x509.bootstrap_identity.as_ref().ok_or_else(|| {
                            format!(
                                "cert {:?} is configured to be issued by EST, \
                                    but EST identity could not be obtained \
                                    and EST bootstrap identity is not configured: {}",
                                id, err
                            )
                        })?;

                        let bid_cert =
                            get_cert_inner(&api.homedir_path, &api.preloaded_certs, bid_cert)?
                                .ok_or_else(|| {
                                    format!(
                                        "could not get EST bootstrap identity cert: {}",
                                        io::Error::from(io::ErrorKind::NotFound)
                                    )
                                })?;

                        let bid_pk = api
                            .key_client
                            .load_key_pair(bid_pk)
                            .await
                            .map_err(BoxedError::from)
                            .and_then(|handle| Ok(CString::new(handle.0)?))
                            .and_then({
                                let key_engine = &mut api.key_engine;

                                move |cstr| Ok(key_engine.load_private_key(&cstr)?)
                            })
                            .map_err(|err| {
                                format!(
                                    "could not get EST bootstrap identity cert private key: {}",
                                    err
                                )
                            })?;

                        if let Ok(ref handle) =
                            api.key_client.load_key_pair(&auth_x509.identity.pk).await
                        {
                            api.key_client.delete_key_pair(handle).await?;
                        }

                        let handle = api
                            .key_client
                            .create_key_pair_if_not_exists(
                                &auth_x509.identity.pk,
                                Some("ec-p256:rsa-4096:*"),
                            )
                            .await?;
                        let cstr = CString::new(handle.0)?;

                        let id_pubkey = api.key_engine.load_public_key(&cstr)?;
                        let id_pk = api.key_engine.load_private_key(&cstr)?;

                        let subject_name = if let Some(ref subject) = cert_options.subject {
                            build_name(subject)?
                        } else {
                            build_name(&CertSubject::CommonName("est-id".to_owned()))?
                        };

                        // Request the new EST identity cert using the EST
                        // bootstrap identity cert.
                        let mut builder = X509Req::builder()?;
                        builder.set_version(0)?;
                        builder.set_subject_name(&subject_name)?;

                        let mut exts = Stack::new()?;
                        exts.push(extension::ExtendedKeyUsage::new().client_auth().build()?)?;

                        builder.add_extensions(&exts)?;
                        builder.set_pubkey(&id_pubkey)?;
                        builder.sign(&id_pk, MessageDigest::sha256())?;

                        let id_init = est::create_cert(
                            chunked_base64_encode(&builder.build().to_der()?),
                            url,
                            auth.basic.as_ref(),
                            Some((&bid_cert, &bid_pk)),
                            &trusted_certs,
                            api.proxy_uri.clone(),
                        )
                        .await
                        .map_err(|bid_err| {
                            format!(
                                "cert {:?} is configured to be issued by EST, \
                                    but neither EST identity nor EST bootstrap \
                                    identity could be obtained: {} {}",
                                id, err, bid_err
                            )
                        })?;
                        write_cert(
                            &api.homedir_path,
                            &api.preloaded_certs,
                            &auth_x509.identity.cert,
                            &id_init,
                        )?;

                        // EST identity cert was obtained and persisted
                        // successfully. Now recurse to retry the original cert
                        // request.
                        create_cert_inner(api, id, (req, pubkey), issuer).await
                    }
                }
            }
        }
    }
}

fn load_inner(path: &Path) -> Result<Option<Vec<u8>>, Error> {
    match fs::read(path) {
        Ok(cert_bytes) => Ok(Some(cert_bytes)),
        Err(ref err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(Error::Internal(InternalError::ReadFile(err))),
    }
}

fn get_cert_inner(
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
        .chain(["".as_bytes()]) // NOTE: empty slice for trailing newline
        .collect::<Vec<_>>()
        .join("\n".as_bytes())
}
