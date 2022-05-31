// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

use serde::de::Error;
use serde::{Deserialize, Serialize};

const _: () = assert!(valid_persistent_index(default_ak_index()));

const fn default_ak_index() -> u32 {
    0x00_01_00
}

/// TPM2 Specification Part 3: 28.5.1.c.1
const fn valid_persistent_index(index: u32) -> bool {
    index <= 0x7F_FF_FF
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct Config {
    #[serde(default, skip_serializing_if = "empty_cstr")]
    pub tcti: std::ffi::CString,

    #[serde(default = "default_ak_index", deserialize_with = "persistent_index", skip_serializing_if = "is_default_ak_index")]
    pub auth_key_index: u32,

    #[serde(default, skip_serializing_if = "is_default_tpm_auth_config")]
    pub tpm_auth: TpmAuthConfig,

    /// Map of service names to endpoint URIs.
    ///
    /// Only configurable in debug builds for the sake of tests.
    #[serde(default, skip_serializing)]
    #[cfg_attr(not(debug_assertions), serde(skip_deserializing))]
    pub endpoints: Endpoints,
}

/*
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct TpmKeyConfig {
    #[serde(deserialize_with = "persistent_index")]
    pub index: u32,
    pub overwrite: bool,
}
*/

#[derive(Debug, Default, Deserialize, PartialEq, Serialize)]
pub struct TpmAuthConfig {
    #[serde(default, skip_serializing_if = "empty_cstr")]
    pub endorsement: std::ffi::CString,
    #[serde(default, skip_serializing_if = "empty_cstr")]
    pub storage: std::ffi::CString,
}

fn empty_cstr(cstr: &std::ffi::CStr) -> bool {
    cstr.to_bytes().is_empty()
}

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
            &"persistent handle index cannot exceed 0x7F_FF_FF",
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
                tcti: std::ffi::CString::default(),
                auth_key_index: super::default_ak_index(),
                tpm_auth: super::TpmAuthConfig::default(),
                endpoints: super::Endpoints {
                    aziot_tpmd: http_common::Connector::Unix {
                        socket_path: std::path::Path::new("/run/aziot/tpmd.sock").into()
                    },
                },
            }
        );
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
                tcti: std::ffi::CString::default(),
                auth_key_index: super::default_ak_index(),
                tpm_auth: super::TpmAuthConfig::default(),
                endpoints: super::Endpoints {
                    aziot_tpmd: http_common::Connector::Unix {
                        socket_path: std::path::Path::new("/custom/path/tpmd.sock").into()
                    },
                },
            }
        );
    }
}
