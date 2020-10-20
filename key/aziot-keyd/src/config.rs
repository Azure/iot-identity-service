// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct Config {
    /// Parameters passed down to libaziot-keys. The allowed names and values are determined by the libaziot-keys implementation.
    #[serde(default)]
    pub aziot_keys: std::collections::BTreeMap<String, String>,

    /// Map of preloaded keys from their ID to their location. The location is in a format that the libaziot-keys implementation understands.
    #[serde(default)]
    pub preloaded_keys: std::collections::BTreeMap<String, String>,

    /// Map of service names to endpoint URIs.
    ///
    /// Only configurable in debug builds for the sake of tests.
    #[serde(default)]
    #[cfg_attr(not(debug_assertions), serde(skip))]
    pub endpoints: Endpoints,
}

/// Map of service names to endpoint URIs.
#[derive(Debug, PartialEq, serde::Deserialize)]
pub struct Endpoints {
    /// The endpoint that the keyd service binds to.
    pub aziot_keyd: http_common::Connector,
}

impl Default for Endpoints {
    fn default() -> Self {
        Endpoints {
            aziot_keyd: http_common::Connector::Unix {
                socket_path: std::path::Path::new("/run/aziot/keyd.sock").into(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parse_config() {
        let actual = r#"
[aziot_keys]
homedir_path = "/var/lib/aziot/keyd"
pkcs11_lib_path = "/usr/lib64/pkcs11/libsofthsm2.so"
pkcs11_base_slot = "pkcs11:token=Key pairs?pin-value=1234"

[preloaded_keys]
bootstrap = "file:///var/secrets/bootstrap.key"
device-id = "pkcs11:token=Key pairs;object=device-id?pin-value=1234"
"#;
        let actual: super::Config = toml::from_str(actual).unwrap();

        assert_eq!(
            actual,
            super::Config {
                aziot_keys: [
                    ("homedir_path", "/var/lib/aziot/keyd"),
                    ("pkcs11_lib_path", "/usr/lib64/pkcs11/libsofthsm2.so"),
                    ("pkcs11_base_slot", "pkcs11:token=Key pairs?pin-value=1234"),
                ]
                .iter()
                .map(|&(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),

                preloaded_keys: [
                    ("bootstrap", "file:///var/secrets/bootstrap.key"),
                    (
                        "device-id",
                        "pkcs11:token=Key pairs;object=device-id?pin-value=1234"
                    ),
                ]
                .iter()
                .map(|&(name, value)| (name.to_owned(), value.to_owned()))
                .collect(),

                endpoints: super::Endpoints {
                    aziot_keyd: http_common::Connector::Unix {
                        socket_path: std::path::Path::new("/run/aziot/keyd.sock").into()
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
aziot_keyd = "unix:///run/aziot/keyd.sock"
"#;
        let actual: super::Config = toml::from_str(actual).unwrap();

        assert_eq!(
            actual,
            super::Config {
                aziot_keys: Default::default(),

                preloaded_keys: Default::default(),

                endpoints: super::Endpoints {
                    aziot_keyd: http_common::Connector::Unix {
                        socket_path: std::path::Path::new("/run/aziot/keyd.sock").into()
                    },
                },
            }
        );
    }
}
