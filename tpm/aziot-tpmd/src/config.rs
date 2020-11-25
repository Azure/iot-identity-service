// Copyright (c) Microsoft. All rights reserved.

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Map of service names to endpoint URIs.
    ///
    /// Only configurable in debug builds for the sake of tests.
    #[serde(default, skip_serializing)]
    #[cfg_attr(not(debug_assertions), serde(skip_deserializing))]
    pub endpoints: Endpoints,
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
                endpoints: super::Endpoints {
                    aziot_tpmd: http_common::Connector::Unix {
                        socket_path: std::path::Path::new("/custom/path/tpmd.sock").into()
                    },
                },
            }
        );
    }
}
