// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

use serde::de::Error;
use serde::{Deserialize, Serialize};

const _: () = assert!(valid_persistent_index(default_ak_index()));
const AUTH_KEY_BOUND_MESSAGE: &str = "integer in range 0x00_00_00..=0x7F_FF_FF";

const fn default_ak_index() -> u32 {
    0x00_01_00
}

/// TPM2 Specification Part 3: 28.5.1.c.1
const fn valid_persistent_index(index: u32) -> bool {
    index <= 0x7F_FF_FF
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Config {
    #[serde(flatten)]
    pub shared: SharedConfig,

    /// Map of service names to endpoint URIs.
    ///
    /// Only configurable in debug builds for the sake of tests.
    #[serde(default, skip_serializing)]
    #[cfg_attr(not(debug_assertions), serde(skip_deserializing))]
    pub endpoints: Endpoints,
}

// NOTE: for sharing with super-config
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct SharedConfig {
    #[serde(default, skip_serializing_if = "empty_cstr")]
    pub tcti: std::ffi::CString,

    #[serde(
        default = "default_ak_index",
        deserialize_with = "persistent_index",
        skip_serializing_if = "is_default_ak_index"
    )]
    pub auth_key_index: u32,

    #[serde(default, skip_serializing_if = "is_default_tpm_auth_config")]
    pub auth: TpmAuthConfig,
}

impl Default for SharedConfig {
    fn default() -> Self {
        Self {
            tcti: std::ffi::CString::default(),
            auth_key_index: default_ak_index(),
            auth: TpmAuthConfig::default(),
        }
    }
}

#[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct TpmAuthConfig {
    #[serde(default, skip_serializing_if = "empty_cstr")]
    pub endorsement: std::ffi::CString,
    #[serde(default, skip_serializing_if = "empty_cstr")]
    pub owner: std::ffi::CString,
}

fn empty_cstr(cstr: &std::ffi::CStr) -> bool {
    cstr.to_bytes().is_empty()
}

// NOTE: reference required by serde
#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_default_ak_index(index: &u32) -> bool {
    *index == default_ak_index()
}

fn is_default_tpm_auth_config(conf: &TpmAuthConfig) -> bool {
    conf == &TpmAuthConfig::default()
}

fn persistent_index<'de, D>(de: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = u32::deserialize(de)?;
    if !valid_persistent_index(value) {
        return Err(D::Error::invalid_value(
            serde::de::Unexpected::Unsigned(u64::from(value)),
            &AUTH_KEY_BOUND_MESSAGE,
        ));
    }
    Ok(value)
}

/// Map of service names to endpoint URIs.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Endpoints {
    /// The endpoint that the tpmd service binds to.
    pub aziot_tpmd: http_common::Connector,
}

impl Default for Endpoints {
    fn default() -> Self {
        Endpoints {
            aziot_tpmd: http_common::Connector::Unix {
                socket_path: std::path::Path::new("/run/aziot/tpmd.sock").into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_config() {
        let actual = r#""#;
        let actual: super::Config = toml::from_str(actual).unwrap();

        assert_eq!(
            actual,
            super::Config {
                shared: super::SharedConfig {
                    tcti: std::ffi::CString::default(),
                    auth_key_index: super::default_ak_index(),
                    auth: super::TpmAuthConfig::default(),
                },
                endpoints: super::Endpoints {
                    aziot_tpmd: http_common::Connector::Unix {
                        socket_path: std::path::Path::new("/run/aziot/tpmd.sock").into()
                    },
                },
            }
        );
    }

    #[test]
    fn parse_config_with_tcti_and_auth_key_index() {
        let actual = r#"
tcti = "swtpm:port=2321"
auth_key_index = 0x01_02_03
"#;
        let actual: super::Config = toml::from_str(actual).unwrap();

        assert_eq!(
            actual,
            super::Config {
                shared: super::SharedConfig {
                    tcti: std::ffi::CString::new("swtpm:port=2321").unwrap(),
                    auth_key_index: 0x01_02_03,
                    auth: super::TpmAuthConfig::default(),
                },
                endpoints: super::Endpoints {
                    aziot_tpmd: http_common::Connector::Unix {
                        socket_path: std::path::Path::new("/run/aziot/tpmd.sock").into()
                    },
                },
            }
        );
    }

    #[test]
    fn parse_config_with_hierarchy_auth_values() {
        let actual = r#"
[auth]
endorsement = "hello"
owner = "world"
"#;
        let actual: super::Config = toml::from_str(actual).unwrap();

        assert_eq!(
            actual,
            super::Config {
                shared: super::SharedConfig {
                    tcti: std::ffi::CString::default(),
                    auth_key_index: super::default_ak_index(),
                    auth: super::TpmAuthConfig {
                        endorsement: std::ffi::CString::new("hello").unwrap(),
                        owner: std::ffi::CString::new("world").unwrap(),
                    },
                },
                endpoints: super::Endpoints {
                    aziot_tpmd: http_common::Connector::Unix {
                        socket_path: std::path::Path::new("/run/aziot/tpmd.sock").into()
                    },
                },
            }
        );
    }

    #[test]
    fn reject_config_with_out_of_bounds_auth_key_index() {
        let actual = r#"
auth_key_index = 0x80_00_00
"#;

        assert!(toml::from_str::<super::Config>(actual)
            .unwrap_err()
            .to_string()
            .contains(super::AUTH_KEY_BOUND_MESSAGE));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn parse_config_with_explicit_endpoints() {
        let actual = r#"
[endpoints]
aziot_tpmd = "unix:///custom/path/tpmd.sock"
"#;
        let actual: super::Config = toml::from_str(actual).unwrap();

        assert_eq!(
            actual,
            super::Config {
                shared: super::SharedConfig {
                    tcti: std::ffi::CString::default(),
                    auth_key_index: super::default_ak_index(),
                    auth: super::TpmAuthConfig::default(),
                },
                endpoints: super::Endpoints {
                    aziot_tpmd: http_common::Connector::Unix {
                        socket_path: std::path::Path::new("/custom/path/tpmd.sock").into()
                    },
                },
            }
        );
    }
}
