// Copyright (c) Microsoft. All rights reserved.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

/// This is the config stored in `/etc/aziot/config.toml`
///
/// It is an amalgam of the individual services' configs, with some tweaks:
///
/// - Wherever key IDs were used to link keys between services, the key is referenced directly.
///   For example, instead of IS provisioning referencing a symmetric key by its key ID and KS optionally associating a key ID with a key URI,
///   the IS provisioning optionally references the key URI directly.
///
/// - Wherever cert IDs were used to link certs between services, the key is referenced directly.
///   For example, instead of IS provisioning referencing a cert by its cert ID and CS associating a cert ID with a cert URI or an issuance method,
///   the IS provisioning references the cert URI or issuance method directly.
///
/// - A consequence of the above is that the EST endpoint spec only allows one of identity or bootstrap identity X.509 auth to be specified, not both.
///   (If bootstrap identity was specified, the regular identity would be IDs.)
///
/// Unfortunately it's not easy to do this without duplicating all the individual services' config types.
/// Inner types are reused when possible, ie when they don't need modification to work with the super-config.
#[derive(Debug, Deserialize, Serialize)]
pub struct Config {
    pub hostname: Option<String>,

    // DEVNOTE:
    //
    // This field is called local_gateway_hostname in the identity-service super-config and parent_hostname in the iotedge super-config.
    // Since this super-config type is shared between the two, we use an alias to allow both names to work.
    //
    // Ideally this would be `#[serde(alias = "parent_hostname")] local_gateway_hostname: Option<String>`, but due to a serde bug [1]
    // this does not work. So we have to do it the other way around.
    //
    // [1]: https://github.com/serde-rs/serde/issues/1976
    #[serde(alias = "local_gateway_hostname")]
    pub parent_hostname: Option<String>,

    #[serde(
        default = "aziot_identityd_config::Settings::default_cloud_timeout",
        deserialize_with = "aziot_identityd_config::deserialize_cloud_timeout",
        skip_serializing_if = "aziot_identityd_config::Settings::is_default_timeout"
    )]
    pub cloud_timeout_sec: u64,

    #[serde(
        default = "aziot_identityd_config::Settings::default_cloud_retries",
        skip_serializing_if = "aziot_identityd_config::Settings::is_default_retries"
    )]
    pub cloud_retries: u32,

    pub provisioning: Provisioning,

    pub localid: Option<aziot_identityd_config::LocalId>,

    #[serde(default)]
    pub aziot_keys: BTreeMap<String, String>,

    #[serde(default)]
    pub preloaded_keys: BTreeMap<String, aziot_keys_common::PreloadedKeyLocation>,

    #[serde(default)]
    pub cert_issuance: CertIssuance,

    #[serde(default)]
    pub preloaded_certs: BTreeMap<String, aziot_certd_config::PreloadedCert>,

    #[serde(default, skip_serializing)]
    #[cfg_attr(not(debug_assertions), serde(skip_deserializing))]
    pub endpoints: aziot_identityd_config::Endpoints,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Provisioning {
    #[serde(flatten)]
    pub provisioning: ProvisioningType,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "source")]
#[serde(rename_all = "lowercase")]
pub enum ProvisioningType {
    Manual {
        #[serde(flatten)]
        inner: ManualProvisioning,
    },

    Dps {
        global_endpoint: Url,
        id_scope: String,
        attestation: DpsAttestationMethod,
    },

    /// Disables provisioning with IoT Hub for devices that use local identities only.
    None,
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ManualProvisioning {
    ConnectionString {
        connection_string: ConnectionString,
    },

    Explicit {
        iothub_hostname: String,
        device_id: String,
        authentication: ManualAuthMethod,
    },
}

#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct ConnectionString(String);

impl ConnectionString {
    pub fn new(s: String) -> Result<ConnectionString, String> {
        // only perform validation, discarding the constituent components.
        let _components = super::parse_manual_connection_string(&s)?;
        Ok(ConnectionString(s))
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl<'de> Deserialize<'de> for ConnectionString {
    fn deserialize<D>(deserializer: D) -> Result<ConnectionString, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ConnectionString;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("connection string")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ConnectionString::new(s.to_owned()).map_err(E::custom)
            }

            fn visit_string<E>(self, s: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ConnectionString::new(s).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "method")]
#[serde(rename_all = "lowercase")]
pub enum ManualAuthMethod {
    #[serde(rename = "sas")]
    SharedPrivateKey { device_id_pk: SymmetricKey },

    X509 {
        #[serde(flatten)]
        identity: X509Identity,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "method")]
#[serde(rename_all = "lowercase")]
pub enum DpsAttestationMethod {
    #[serde(rename = "symmetric_key")]
    SymmetricKey {
        registration_id: String,
        symmetric_key: SymmetricKey,
    },

    X509 {
        registration_id: Option<String>,

        #[serde(flatten)]
        identity: X509Identity,
    },

    Tpm {
        registration_id: String,
    },
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct CertIssuance {
    pub est: Option<Est>,
    pub local_ca: Option<LocalCa>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Est {
    #[serde(default)]
    pub trusted_certs: Vec<Url>,
    pub auth: EstAuth,
    pub urls: BTreeMap<String, Url>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EstAuth {
    #[serde(flatten)]
    pub basic: Option<aziot_certd_config::EstAuthBasic>,

    #[serde(flatten)]
    pub x509: Option<EstAuthX509>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EstAuthX509 {
    BootstrapIdentity {
        bootstrap_identity_cert: Url,
        bootstrap_identity_pk: aziot_keys_common::PreloadedKeyLocation,
    },

    Identity {
        identity_cert: Url,
        identity_pk: aziot_keys_common::PreloadedKeyLocation,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum LocalCa {
    Issued {
        cert: CertIssuanceOptions,
    },

    Preloaded {
        cert: Url,
        pk: aziot_keys_common::PreloadedKeyLocation,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SymmetricKey {
    Inline {
        #[serde(with = "base64")]
        value: Vec<u8>,
    },

    Preloaded {
        uri: aziot_keys_common::PreloadedKeyLocation,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum X509Identity {
    Issued {
        identity_cert: CertIssuanceOptions,
    },

    Preloaded {
        identity_cert: Url,
        identity_pk: aziot_keys_common::PreloadedKeyLocation,
    },
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct CertIssuanceOptions {
    pub common_name: Option<String>,

    #[serde(
        default,
        deserialize_with = "aziot_certd_config::deserialize_expiry_days"
    )]
    pub expiry_days: Option<u32>,

    #[serde(flatten)]
    pub method: CertIssuanceMethod,
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum CertIssuanceMethod {
    #[serde(rename = "est")]
    Est {
        url: Option<url::Url>,
        #[serde(flatten)]
        auth: Option<EstAuth>,
    },

    LocalCa,

    SelfSigned,
}

mod base64 {
    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Vec<u8>;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("base64-encoded byte array")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let b = base64::decode(s).map_err(serde::de::Error::custom)?;
                Ok(b)
            }
        }

        deserializer.deserialize_str(Visitor)
    }

    pub(super) fn serialize<S>(b: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let s = base64::encode(b);
        serializer.serialize_str(&s)
    }
}
