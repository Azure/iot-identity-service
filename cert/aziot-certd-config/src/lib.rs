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
use std::convert::TryFrom;
use std::path::{Path, PathBuf};

use http_common::Connector;
use serde::{Deserialize, Serialize};
use serde::de::Error as _;
use serde_with::{skip_serializing_none, with_prefix};
use url::Url;

#[derive(Debug, Deserialize, PartialEq, Serialize)]
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
#[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct CertIssuance {
    /// Configuration of parameters for issuing certs via EST.
    pub est: Option<Est>,

    /// Configuration of parameters for issuing certs via a local CA cert.
    pub local_ca: Option<CertAuthority>,

    /// Map of certificate IDs to the details used to issue them.
    #[serde(flatten)]
    pub certs: BTreeMap<String, CertIssuanceOptions>,
}

/// Configuration of parameters for issuing certs via EST.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Est {
    /// List of certs that should be treated as trusted roots for validating the EST server's TLS certificate.
    #[serde(default)]
    pub trusted_certs: Vec<String>,

    /// Authentication parameters for the EST server.
    // NOTE: DO NOT MOVE. Tables must be after values!
    #[serde(flatten)]
    pub auth: EstAuth,

    /// Map of certificate IDs to EST endpoint URLs.
    ///
    /// The special key "default" is used as a fallback for certs whose ID is not explicitly listed in this map.
    pub urls: BTreeMap<String, Url>,
}

/// Authentication parameters for the EST server.
///
/// Note that EST servers may be configured to have only basic auth, only TLS client cert auth, or both.
#[skip_serializing_none]
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(try_from = "_EstAuth")]
pub struct EstAuth {
    /// Authentication parameters when using basic HTTP authentication.
    #[serde(flatten)]
    pub basic: Option<EstAuthBasic>,

    /// Authentication parameters when using TLS client cert authentication.
    #[serde(flatten)]
    pub x509: Option<EstAuthX509>,

    /// Headers to inject into authentication request.
    pub headers: Option<BTreeMap<String, String>>
}

#[derive(Deserialize)]
struct _EstAuth {
    #[serde(flatten)]
    pub basic: Option<EstAuthBasic>,
    #[serde(flatten)]
    pub x509: Option<EstAuthX509>,
    pub headers: Option<BTreeMap<String, String>>
}

impl TryFrom<_EstAuth> for EstAuth {
    type Error = serde::de::value::Error;

    fn try_from(value: _EstAuth) -> Result<Self, Self::Error> {
        let _EstAuth { basic, x509, headers } = value;
        if basic.is_none() && x509.is_none() && headers.is_none() {
            Err(Self::Error::missing_field("empty authentication parameters"))
        }
        else {
            Ok(Self { basic, x509, headers })
        }
    }
}

/// Authentication parameters when using basic HTTP authentication.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EstAuthBasic {
    pub username: String,
    pub password: String,
}

/// Authentication parameters when using TLS client cert authentication.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EstAuthX509 {
    /// Cert ID and private key ID for the identity cert.
    ///
    /// If this cert does not exist, it will be requested from the EST server,
    /// with the bootstrap identity cert used as the initial TLS client cert.
    #[serde(flatten, with = "prefix_identity")]
    pub identity: CertAuthority,

    /// Cert ID and private key ID for the bootstrap identity cert.
    ///
    /// This is needed if the cert indicated by `identity` does not exist
    /// and thus also needs to be requested from the EST server.
    #[serde(flatten, with = "prefix_bootstrap_identity")]
    pub bootstrap_identity: Option<CertAuthority>,
}

with_prefix!(prefix_identity "identity_");
with_prefix!(prefix_bootstrap_identity "bootstrap_identity_");

/// Configuration of parameters for issuing certs via a local CA cert.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CertAuthority {
    /// Certificate ID.
    pub cert: String,

    /// Private key ID.
    pub pk: String,
}

/// Details for issuing a single cert.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CertIssuanceOptions {
    #[serde(flatten)]
    pub subject: Option<CertSubject>,

    /// Number of days between cert issuance and expiry. Applies to local_ca and self_signed issuance methods.
    /// If not provided, defaults to 30.
    #[serde(default, deserialize_with = "deserialize_expiry_days")]
    pub expiry_days: Option<u32>,

    /// The method used to issue a certificate.
    #[serde(flatten)]
    pub method: CertIssuanceMethod,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CertSubject {
    CommonName(String),
    Subject(BTreeMap<String, String>)
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
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum CertIssuanceMethod {
    /// The certificate is to be issued via EST.
    Est {
        url: Option<Url>,
        #[serde(flatten)]
        auth: Option<EstAuth>,
    },

    /// The certificate is to be issued via a local CA cert.
    LocalCa,

    /// The certificate is to be self-signed.
    SelfSigned,
}

/// The location of a preloaded cert.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum PreloadedCert {
    /// A URI for the location.
    ///
    /// Only `file://` URIs are supported.
    Uri(Url),

    /// A list of IDs of other certs, preloaded or otherwise.
    ///
    /// If an element of the list references a preloaded cert's ID, that preloaded cert must be a URI rather than another list.
    Ids(Vec<String>),
}

/// Map of service names to endpoint URIs.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Endpoints {
    /// The endpoint that the certd service binds to.
    pub aziot_certd: Connector,

    /// The endpoint that the keyd service binds to.
    pub aziot_keyd: Connector,
}

impl Default for Endpoints {
    fn default() -> Self {
        Endpoints {
            aziot_certd: Connector::Unix {
                socket_path: Path::new("/run/aziot/certd.sock").into(),
            },
            aziot_keyd: Connector::Unix {
                socket_path: Path::new("/run/aziot/keyd.sock").into(),
            },
        }
    }
}

// cf. https://github.com/alexcrichton/toml-rs/blob/0.5.8/src/ser.rs#L1580-L1606
// LICENSE: https://raw.githubusercontent.com/alexcrichton/toml-rs/0.5.8/LICENSE-MIT
// fn tables_last_opt<'a, I, K, V> { }

/// Map of a Unix UID to certificate IDs with write access.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Principal {
    /// Unix UID.
    pub uid: libc::uid_t,

    /// Certificate IDs for which the given UID has write access. Wildcards may be used.
    pub certs: Vec<String>,
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
expiry_days = 365
url = "https://estendpoint.com/.well-known/est/device-id/"
username = "username"
password = "password"
identity_cert = "device-id"
identity_pk = "device-id"
bootstrap_identity_cert = "bootstrap"
bootstrap_identity_pk = "bootstrap"
headers = { just = "testing" }

[cert_issuance.device-id.subject]
L = "AQ"
ST = "Antarctica"
CN = "test-device"

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
                        trusted_certs: vec!["est-ca".to_owned(),],
                        auth: EstAuth {
                            basic: None,
                            x509: Some(EstAuthX509 {
                                identity: CertAuthority { cert: "est-id".to_owned(), pk: "est-id".to_owned() },
                                bootstrap_identity: Some(CertAuthority {
                                    cert: "bootstrap".to_owned(),
                                    pk: "bootstrap".to_owned()
                                }),
                            }),
                            headers: None
                        },
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
                        .collect()
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
                                subject: Some(CertSubject::CommonName("custom-name".to_owned())),
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
                                        basic: Some(EstAuthBasic {
                                            username: "username".to_owned(),
                                            password: "password".to_owned(),
                                        }),
                                        x509: Some(EstAuthX509 {
                                            identity: CertAuthority {
                                                cert: "device-id".to_owned(),
                                                pk: "device-id".to_owned()
                                            },
                                            bootstrap_identity: Some(CertAuthority {
                                                cert: "bootstrap".to_owned(),
                                                pk: "bootstrap".to_owned()
                                            }),
                                        }),
                                        headers: Some(vec![("just".to_owned(), "testing".to_owned())].into_iter().collect())
                                    })
                                },
                                subject: Some(CertSubject::Subject(
                                    vec![
                                        ("L".to_owned(), "AQ".to_owned()),
                                        ("ST".to_owned(), "Antarctica".to_owned()),
                                        ("CN".to_owned(), "test-device".to_owned())
                                    ].into_iter().collect()
                                )),
                                expiry_days: Some(365)
                            }
                        ),
                        (
                            "module-id",
                            CertIssuanceOptions {
                                method: CertIssuanceMethod::SelfSigned,
                                subject: Some(CertSubject::CommonName("custom-name".to_owned())),
                                expiry_days: Some(90),
                            }
                        ),
                        (
                            "module-server",
                            CertIssuanceOptions {
                                method: CertIssuanceMethod::LocalCa,
                                subject: None,
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
                    aziot_certd: Connector::Unix {
                        socket_path: Path::new("/run/aziot/certd.sock").into()
                    },
                    aziot_keyd: Connector::Unix {
                        socket_path: Path::new("/run/aziot/keyd.sock").into()
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
                    aziot_certd: Connector::Unix {
                        socket_path: Path::new("/run/aziot/certd.sock").into()
                    },
                    aziot_keyd: Connector::Unix {
                        socket_path: Path::new("/run/aziot/keyd.sock").into()
                    },
                },

                principal: Default::default(),
            }
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn serialize_config() {
        let configuration = Config {
            homedir_path: "/var/lib/aziot/certd".into(),

            cert_issuance: CertIssuance {
                est: Some(Est {
                    trusted_certs: vec!["est-ca".to_owned(),],
                    auth: EstAuth {
                        basic: None,
                        x509: Some(EstAuthX509 {
                            identity: CertAuthority { cert: "est-id".to_owned(), pk: "est-id".to_owned() },
                            bootstrap_identity: Some(CertAuthority {
                                cert: "bootstrap".to_owned(),
                                pk: "bootstrap".to_owned()
                            }),
                        }),
                        headers: None
                    },
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
                    .collect()
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
                            subject: Some(CertSubject::CommonName("custom-name".to_owned())),
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
                                    basic: Some(EstAuthBasic {
                                        username: "username".to_owned(),
                                        password: "password".to_owned(),
                                    }),
                                    x509: Some(EstAuthX509 {
                                        identity: CertAuthority {
                                            cert: "device-id".to_owned(),
                                            pk: "device-id".to_owned()
                                        },
                                        bootstrap_identity: Some(CertAuthority {
                                            cert: "bootstrap".to_owned(),
                                            pk: "bootstrap".to_owned()
                                        }),
                                    }),
                                    headers: Some(vec![("just".to_owned(), "testing".to_owned())].into_iter().collect())
                                })
                            },
                            subject: Some(CertSubject::CommonName("test-device".to_owned())),
                            expiry_days: Some(365)
                        }
                    ),
                    (
                        "module-id",
                        CertIssuanceOptions {
                            method: CertIssuanceMethod::SelfSigned,
                            subject: Some(CertSubject::CommonName("custom-name".to_owned())),
                            expiry_days: Some(90),
                        }
                    ),
                    (
                        "module-server",
                        CertIssuanceOptions {
                            method: CertIssuanceMethod::LocalCa,
                            subject: None,
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
                aziot_certd: Connector::Unix {
                    socket_path: Path::new("/run/aziot/certd.sock").into()
                },
                aziot_keyd: Connector::Unix {
                    socket_path: Path::new("/run/aziot/keyd.sock").into()
                },
            },

            principal: vec![Principal {
                uid: 1000,
                certs: vec!["test".to_string()]
            }],
        };

        let serialized = toml::to_string(&configuration).unwrap();

        assert_eq!(
            configuration,
            toml::from_str(&serialized).unwrap()
        );
    }
}
