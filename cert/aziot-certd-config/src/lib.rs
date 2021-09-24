// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::too_many_lines,
    clippy::let_unit_value,
    clippy::missing_errors_doc
)]

pub mod util;

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Config {
    /// Path of home directory.
    pub homedir_path: PathBuf,

    /// Configuration of how new certificates should be issued.
    #[serde(default)]
    pub cert_issuance: CertIssuance,

    /// Map of preloaded certs from their ID to their location.
    #[serde(default)]
    pub preloaded_certs: BTreeMap<String, PreloadedCert>,

    /// Map of service names to endpoint URIs.
    ///
    /// Only configurable in debug builds for the sake of tests.
    #[serde(default, skip_serializing)]
    #[cfg_attr(not(debug_assertions), serde(skip_deserializing))]
    pub endpoints: Endpoints,

    /// Authorized Unix users and the corresponding certificate IDs.
    ///
    /// A Unix user with the given UID is granted write access to the certificate IDs
    /// specified. Wildcards may be used for certificate IDs.
    ///
    /// This authorization only affects write access. Read access for all certificate IDs is
    /// granted to all users.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal: Vec<Principal>,
}

/// Configuration of how new certificates should be issued.
#[derive(Debug, Default, PartialEq, Deserialize, Serialize)]
pub struct CertIssuance {
    /// Configuration of parameters for issuing certs via EST.
    pub est: Option<Est>,

    /// Configuration of parameters for issuing certs via a local CA cert.
    pub local_ca: Option<LocalCa>,

    /// Map of certificate IDs to the details used to issue them.
    #[serde(flatten)]
    pub certs: std::collections::BTreeMap<String, CertIssuanceOptions>,
}

/// Configuration of parameters for issuing certs via EST.
#[derive(Debug, PartialEq)]
pub struct Est {
    /// Authentication parameters for the EST server.
    pub auth: EstAuth,

    /// List of certs that should be treated as trusted roots for validating the EST server's TLS certificate.
    pub trusted_certs: Vec<String>,

    /// Map of certificate IDs to EST endpoint URLs.
    ///
    /// The special key "default" is used as a fallback for certs whose ID is not explicitly listed in this map.
    pub urls: std::collections::BTreeMap<String, url::Url>,
}

/// Authentication parameters for the EST server.
///
/// Note that EST servers may be configured to have only basic auth, only TLS client cert auth, or both.
#[derive(Clone, Debug, PartialEq)]
pub struct EstAuth {
    // Headers to inject into authentication request.
    pub headers: Option<std::collections::BTreeMap<String, String>>,

    /// Authentication parameters when using basic HTTP authentication.
    pub basic: Option<EstAuthBasic>,

    /// Authentication parameters when using TLS client cert authentication.
    pub x509: Option<EstAuthX509>,
}

/// Authentication parameters when using basic HTTP authentication.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct EstAuthBasic {
    pub username: String,
    pub password: String,
}

/// Authentication parameters when using TLS client cert authentication.
#[derive(Clone, Debug, PartialEq)]
pub struct EstAuthX509 {
    /// Cert ID and private key ID for the identity cert.
    ///
    /// If this cert does not exist, it will be requested from the EST server,
    /// with the bootstrap identity cert used as the initial TLS client cert.
    pub identity: (String, String),

    /// Cert ID and private key ID for the bootstrap identity cert.
    ///
    /// This is needed if the cert indicated by `identity` does not exist
    /// and thus also needs to be requested from the EST server.
    pub bootstrap_identity: Option<(String, String)>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub(crate) struct EstInner {
    #[serde(flatten)]
    auth: EstAuthInner,

    #[serde(default)]
    trusted_certs: Vec<String>,

    urls: std::collections::BTreeMap<String, url::Url>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub(crate) struct EstAuthInner {
    username: Option<String>,
    password: Option<String>,

    identity_cert: Option<String>,
    identity_pk: Option<String>,
    bootstrap_identity_cert: Option<String>,
    bootstrap_identity_pk: Option<String>,

    headers: Option<std::collections::BTreeMap<String, String>>
}

impl<'de> Deserialize<'de> for Est {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        let inner: EstInner = Deserialize::deserialize(deserializer)?;

        let auth = deserialize_auth_inner(inner.auth).map_err(serde::de::Error::missing_field)?;

        let trusted_certs = inner.trusted_certs;

        let urls = inner.urls;

        Ok(Est {
            auth,
            trusted_certs,
            urls,
        })
    }
}

impl Serialize for Est {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut inner = EstInner::default();

        serialize_auth_inner(&self.auth, &mut inner.auth);
        inner.trusted_certs = self.trusted_certs.clone();
        inner.urls = self.urls.clone();

        inner.serialize(serializer)
    }
}

/// Configuration of parameters for issuing certs via a local CA cert.
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct LocalCa {
    /// Certificate ID.
    pub cert: String,

    /// Private key ID.
    pub pk: String,
}

/// Details for issuing a single cert.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub struct CertIssuanceOptions {
    pub common_name: Option<String>,

    /// Number of days between cert issuance and expiry. Applies to local_ca and self_signed issuance methods.
    /// If not provided, defaults to 30.
    #[serde(default, deserialize_with = "deserialize_expiry_days")]
    pub expiry_days: Option<u32>,

    /// The method used to issue a certificate.
    #[serde(flatten)]
    pub method: CertIssuanceMethod,
}

pub fn deserialize_expiry_days<'de, D>(deserializer: D) -> Result<Option<u32>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let result: Option<u32> = Deserialize::deserialize(deserializer)?;

    if result == Some(0) {
        return Err(serde::de::Error::custom(
            "expiry_days must be greater than 0",
        ));
    }

    Ok(result)
}

/// The method used to issue a certificate.
#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum CertIssuanceMethod {
    /// The certificate is to be issued via EST.
    #[serde(rename = "est")]
    Est {
        url: Option<url::Url>,
        #[serde(
            flatten,
            deserialize_with = "deserialize_est_auth",
            serialize_with = "serialize_est_auth"
        )]
        auth: Option<EstAuth>,
    },

    /// The certificate is to be issued via a local CA cert.
    LocalCa,

    /// The certificate is to be self-signed.
    SelfSigned,
}

fn deserialize_est_auth<'de, D>(deserializer: D) -> Result<Option<EstAuth>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    let inner: Option<EstAuthInner> = Deserialize::deserialize(deserializer)?;

    if let Some(inner) = inner {
        let auth = deserialize_auth_inner(inner).map_err(serde::de::Error::missing_field)?;

        if auth.headers.is_some() || auth.basic.is_some() || auth.x509.is_some() {
            return Ok(Some(auth));
        }
    }

    Ok(None)
}

fn serialize_est_auth<S>(auth: &Option<EstAuth>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::ser::Serializer,
{
    let mut inner = EstAuthInner::default();

    if let Some(auth) = auth {
        serialize_auth_inner(auth, &mut inner);
    }

    inner.serialize(serializer)
}

/// The location of a preloaded cert.
#[derive(Debug, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PreloadedCert {
    /// A URI for the location.
    ///
    /// Only `file://` URIs are supported.
    Uri(url::Url),

    /// A list of IDs of other certs, preloaded or otherwise.
    ///
    /// If an element of the list references a preloaded cert's ID, that preloaded cert must be a URI rather than another list.
    Ids(Vec<String>),
}

/// Map of service names to endpoint URIs.
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Endpoints {
    /// The endpoint that the certd service binds to.
    pub aziot_certd: http_common::Connector,

    /// The endpoint that the keyd service binds to.
    pub aziot_keyd: http_common::Connector,
}

impl Default for Endpoints {
    fn default() -> Self {
        Endpoints {
            aziot_certd: http_common::Connector::Unix {
                socket_path: std::path::Path::new("/run/aziot/certd.sock").into(),
            },
            aziot_keyd: http_common::Connector::Unix {
                socket_path: std::path::Path::new("/run/aziot/keyd.sock").into(),
            },
        }
    }
}

/// Map of a Unix UID to certificate IDs with write access.
#[derive(Debug, PartialEq, Deserialize, Serialize)]
pub struct Principal {
    /// Unix UID.
    pub uid: libc::uid_t,

    /// Certificate IDs for which the given UID has write access. Wildcards may be used.
    pub certs: Vec<String>,
}

fn deserialize_auth_inner(auth: EstAuthInner) -> Result<EstAuth, &'static str> {
    let auth_basic = match (auth.username, auth.password) {
        (Some(username), Some(password)) => Some(EstAuthBasic { username, password }),

        (Some(_), None) => return Err("password"),

        (None, Some(_)) => return Err("username"),

        (None, None) => None,
    };

    let auth_x509 = match (auth.identity_cert, auth.identity_pk) {
        (Some(identity_cert), Some(identity_pk)) => {
            let identity = (identity_cert, identity_pk);

            let bootstrap_identity =
                match (auth.bootstrap_identity_cert, auth.bootstrap_identity_pk) {
                    (Some(bootstrap_identity_cert), Some(bootstrap_identity_pk)) => {
                        Some((bootstrap_identity_cert, bootstrap_identity_pk))
                    }
                    (Some(_), None) => return Err("bootstrap_identity_pk"),
                    (None, Some(_)) => return Err("bootstrap_identity_cert"),
                    (None, None) => None,
                };

            Some(EstAuthX509 {
                identity,
                bootstrap_identity,
            })
        }

        (Some(_), None) => return Err("identity_pk"),

        (None, Some(_)) => return Err("identity_cert"),

        (None, None) => None,
    };

    Ok(EstAuth {
        headers: auth.headers,
        basic: auth_basic,
        x509: auth_x509,
    })
}

fn serialize_auth_inner(auth: &EstAuth, inner: &mut EstAuthInner) {
    if let Some(basic) = &auth.basic {
        inner.username = Some(basic.username.clone());
        inner.password = Some(basic.password.clone());
    }

    if let Some(x509) = &auth.x509 {
        inner.identity_cert = Some(x509.identity.0.clone());
        inner.identity_pk = Some(x509.identity.1.clone());

        if let Some(bootstrap_identity) = &x509.bootstrap_identity {
            inner.bootstrap_identity_cert = Some(bootstrap_identity.0.clone());
            inner.bootstrap_identity_pk = Some(bootstrap_identity.1.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_config() {
        let actual = r#"
homedir_path = "/var/lib/aziot/certd"

[cert_issuance]
device-ca = { method = "est", common_name = "custom-name" }
module-id = { method = "self_signed", expiry_days = 90, common_name = "custom-name"}
module-server = { method = "local_ca" }

[cert_issuance.device-id]
method = "est"
common_name = "test-device"
expiry_days = 365
url = "https://estendpoint.com/.well-known/est/device-id/"
username = "username"
password = "password"
identity_cert = "device-id"
identity_pk = "device-id"
bootstrap_identity_cert = "bootstrap"
bootstrap_identity_pk = "bootstrap"
headers = { just = "testing" }

[cert_issuance.est]
identity_cert = "est-id"
identity_pk = "est-id"
bootstrap_identity_cert = "bootstrap"
bootstrap_identity_pk = "bootstrap"
trusted_certs = [
	"est-ca",
]

[cert_issuance.est.urls]
default = "https://estendpoint.com/.well-known/est/"
device-ca = "https://estendpoint.com/.well-known/est/device-ca/"

[preloaded_certs]
bootstrap = "file:///var/secrets/bootstrap.cer"
est-ca = "file:///var/secrets/est-ca.cer"
trust-bundle = [
	"est-ca",
]

[[principal]]
uid = 1000
certs = ["test"]
"#;

        let actual: Config = toml::from_str(actual).unwrap();
        assert_eq!(
            actual,
            Config {
                homedir_path: "/var/lib/aziot/certd".into(),

                cert_issuance: CertIssuance {
                    est: Some(Est {
                        auth: EstAuth {
                            headers: None,
                            basic: None,
                            x509: Some(EstAuthX509 {
                                identity: ("est-id".to_owned(), "est-id".to_owned()),
                                bootstrap_identity: Some((
                                    "bootstrap".to_owned(),
                                    "bootstrap".to_owned()
                                )),
                            }),
                        },
                        trusted_certs: vec!["est-ca".to_owned(),],
                        urls: vec![
                            (
                                "default".to_owned(),
                                "https://estendpoint.com/.well-known/est/".parse().unwrap()
                            ),
                            (
                                "device-ca".to_owned(),
                                "https://estendpoint.com/.well-known/est/device-ca/"
                                    .parse()
                                    .unwrap()
                            ),
                        ]
                        .into_iter()
                        .collect(),
                    }),

                    local_ca: None,

                    certs: [
                        (
                            "device-ca",
                            CertIssuanceOptions {
                                method: CertIssuanceMethod::Est {
                                    url: None,
                                    auth: None
                                },
                                common_name: Some("custom-name".to_owned()),
                                expiry_days: None,
                            }
                        ),
                        (
                            "device-id",
                            CertIssuanceOptions {
                                method: CertIssuanceMethod::Est {
                                    url: Some(
                                        "https://estendpoint.com/.well-known/est/device-id/"
                                            .parse()
                                            .unwrap()
                                    ),
                                    auth: Some(EstAuth {
                                        headers: Some(vec![("just".to_owned(), "testing".to_owned())].into_iter().collect()),
                                        basic: Some(EstAuthBasic {
                                            username: "username".to_owned(),
                                            password: "password".to_owned(),
                                        }),
                                        x509: Some(EstAuthX509 {
                                            identity: (
                                                "device-id".to_owned(),
                                                "device-id".to_owned()
                                            ),
                                            bootstrap_identity: Some((
                                                "bootstrap".to_owned(),
                                                "bootstrap".to_owned()
                                            )),
                                        })
                                    })
                                },
                                common_name: Some("test-device".to_owned()),
                                expiry_days: Some(365)
                            }
                        ),
                        (
                            "module-id",
                            CertIssuanceOptions {
                                method: CertIssuanceMethod::SelfSigned,
                                common_name: Some("custom-name".to_owned()),
                                expiry_days: Some(90),
                            }
                        ),
                        (
                            "module-server",
                            CertIssuanceOptions {
                                method: CertIssuanceMethod::LocalCa,
                                common_name: None,
                                expiry_days: None,
                            }
                        ),
                    ]
                    .iter()
                    .map(|(id, options)| ((*id).to_owned(), options.clone()))
                    .collect(),
                },

                preloaded_certs: vec![
                    (
                        "bootstrap".to_owned(),
                        PreloadedCert::Uri(
                            "file:///var/secrets/bootstrap.cer".parse().unwrap()
                        )
                    ),
                    (
                        "est-ca".to_owned(),
                        PreloadedCert::Uri(
                            "file:///var/secrets/est-ca.cer".parse().unwrap()
                        )
                    ),
                    (
                        "trust-bundle".to_owned(),
                        PreloadedCert::Ids(vec!["est-ca".to_owned()])
                    ),
                ]
                .into_iter()
                .collect(),

                endpoints: Endpoints {
                    aziot_certd: http_common::Connector::Unix {
                        socket_path: std::path::Path::new("/run/aziot/certd.sock").into()
                    },
                    aziot_keyd: http_common::Connector::Unix {
                        socket_path: std::path::Path::new("/run/aziot/keyd.sock").into()
                    },
                },

                principal: vec![Principal {
                    uid: 1000,
                    certs: vec!["test".to_string()]
                }],
            }
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn parse_config_with_explicit_endpoints() {
        let actual = r#"
homedir_path = "/var/lib/aziot/certd"

[endpoints]
aziot_keyd = "unix:///run/aziot/keyd.sock"
aziot_certd = "unix:///run/aziot/certd.sock"
"#;

        let actual: Config = toml::from_str(actual).unwrap();
        assert_eq!(
            actual,
            Config {
                homedir_path: "/var/lib/aziot/certd".into(),

                cert_issuance: Default::default(),

                preloaded_certs: Default::default(),

                endpoints: Endpoints {
                    aziot_certd: http_common::Connector::Unix {
                        socket_path: std::path::Path::new("/run/aziot/certd.sock").into()
                    },
                    aziot_keyd: http_common::Connector::Unix {
                        socket_path: std::path::Path::new("/run/aziot/keyd.sock").into()
                    },
                },

                principal: Default::default(),
            }
        );
    }
}
