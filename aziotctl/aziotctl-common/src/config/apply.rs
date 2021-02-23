// Copyright (c) Microsoft. All rights reserved.

use anyhow::anyhow;

use super::super_config;

#[derive(Debug)]
pub struct RunOutput {
    pub certd_config: aziot_certd_config::Config,
    pub identityd_config: aziot_identityd_config::Settings,
    pub keyd_config: aziot_keyd_config::Config,
    pub tpmd_config: aziot_tpmd_config::Config,
    pub preloaded_device_id_pk_bytes: Option<Vec<u8>>,
}

/// Takes the super-config and converts it into the individual services' config files.
pub fn run(
    config: super_config::Config,
    aziotcs_uid: nix::unistd::Uid,
    aziotid_uid: nix::unistd::Uid,
) -> anyhow::Result<RunOutput> {
    let super_config::Config {
        hostname,
        provisioning,
        localid,
        mut aziot_keys,
        mut preloaded_keys,
        cert_issuance,
        mut preloaded_certs,
        endpoints:
            aziot_identityd_config::Endpoints {
                aziot_certd: aziot_certd_endpoint,
                aziot_identityd: aziot_identityd_endpoint,
                aziot_keyd: aziot_keyd_endpoint,
                aziot_tpmd: aziot_tpmd_endpoint,
            },
    } = config;

    let mut preloaded_device_id_pk = None;

    let mut cert_issuance_certs: std::collections::BTreeMap<
        String,
        aziot_certd_config::CertIssuanceOptions,
    > = Default::default();

    // Authorization of IS with KS.
    let mut aziotid_keys = aziot_keyd_config::Principal {
        uid: aziotid_uid.as_raw(),
        keys: vec!["aziot_identityd_master_id".to_owned()],
    };

    // Authorization of IS with CS.
    let mut aziotid_certs = aziot_certd_config::Principal {
        uid: aziotid_uid.as_raw(),
        certs: vec![],
    };

    let provisioning = {
        let super_config::Provisioning {
            always_reprovision_on_startup,
            provisioning,
        } = provisioning;

        let provisioning = match provisioning {
            super_config::ProvisioningType::Manual {
                inner: super_config::ManualProvisioning::ConnectionString { connection_string },
            } => {
                let (iothub_hostname, device_id, device_id_pk_bytes) =
                    super::parse_manual_connection_string(&connection_string)
                        .map_err(|err| anyhow!("connection string is invalid: {}", err))?;

                preloaded_device_id_pk = Some(super_config::SymmetricKey::Inline {
                    value: device_id_pk_bytes,
                });

                aziotid_keys.keys.push(super::DEVICE_ID_ID.to_owned());

                aziot_identityd_config::ProvisioningType::Manual {
                    iothub_hostname,
                    device_id,
                    authentication: aziot_identityd_config::ManualAuthMethod::SharedPrivateKey {
                        device_id_pk: super::DEVICE_ID_ID.to_owned(),
                    },
                }
            }

            super_config::ProvisioningType::Manual {
                inner:
                    super_config::ManualProvisioning::Explicit {
                        iothub_hostname,
                        device_id,
                        authentication,
                    },
            } => {
                let authentication = match authentication {
                    super_config::ManualAuthMethod::SharedPrivateKey { device_id_pk } => {
                        preloaded_device_id_pk = Some(device_id_pk);

                        aziotid_keys.keys.push(super::DEVICE_ID_ID.to_owned());

                        aziot_identityd_config::ManualAuthMethod::SharedPrivateKey {
                            device_id_pk: super::DEVICE_ID_ID.to_owned(),
                        }
                    }

                    super_config::ManualAuthMethod::X509 { identity } => {
                        match identity {
                            super_config::X509Identity::Issued { identity_cert } => {
                                aziotid_keys.keys.push(super::DEVICE_ID_ID.to_owned());

                                cert_issuance_certs
                                    .insert(super::DEVICE_ID_ID.to_owned(), identity_cert);
                                aziotid_certs.certs.push(super::DEVICE_ID_ID.to_owned());
                            }

                            super_config::X509Identity::Preloaded {
                                identity_cert,
                                identity_pk,
                            } => {
                                preloaded_keys.insert(super::DEVICE_ID_ID.to_owned(), identity_pk);
                                aziotid_keys.keys.push(super::DEVICE_ID_ID.to_owned());

                                preloaded_certs.insert(
                                    super::DEVICE_ID_ID.to_owned(),
                                    aziot_certd_config::PreloadedCert::Uri(identity_cert),
                                );
                            }
                        }

                        aziot_identityd_config::ManualAuthMethod::X509 {
                            identity_cert: super::DEVICE_ID_ID.to_owned(),
                            identity_pk: super::DEVICE_ID_ID.to_owned(),
                        }
                    }
                };

                aziot_identityd_config::ProvisioningType::Manual {
                    iothub_hostname,
                    device_id,
                    authentication,
                }
            }

            super_config::ProvisioningType::Dps {
                global_endpoint,
                id_scope,
                attestation,
            } => {
                let attestation = match attestation {
                    super_config::DpsAttestationMethod::SymmetricKey {
                        registration_id,
                        symmetric_key,
                    } => {
                        preloaded_device_id_pk = Some(symmetric_key);

                        aziotid_keys.keys.push(super::DEVICE_ID_ID.to_owned());

                        aziot_identityd_config::DpsAttestationMethod::SymmetricKey {
                            registration_id,
                            symmetric_key: super::DEVICE_ID_ID.to_owned(),
                        }
                    }

                    super_config::DpsAttestationMethod::X509 {
                        registration_id,
                        identity,
                    } => {
                        match identity {
                            super_config::X509Identity::Issued { identity_cert } => {
                                aziotid_keys.keys.push(super::DEVICE_ID_ID.to_owned());

                                cert_issuance_certs
                                    .insert(super::DEVICE_ID_ID.to_owned(), identity_cert);
                                aziotid_certs.certs.push(super::DEVICE_ID_ID.to_owned());
                            }

                            super_config::X509Identity::Preloaded {
                                identity_cert,
                                identity_pk,
                            } => {
                                preloaded_keys.insert(super::DEVICE_ID_ID.to_owned(), identity_pk);
                                aziotid_keys.keys.push(super::DEVICE_ID_ID.to_owned());

                                preloaded_certs.insert(
                                    super::DEVICE_ID_ID.to_owned(),
                                    aziot_certd_config::PreloadedCert::Uri(identity_cert),
                                );
                            }
                        }

                        aziot_identityd_config::DpsAttestationMethod::X509 {
                            registration_id,
                            identity_cert: super::DEVICE_ID_ID.to_owned(),
                            identity_pk: super::DEVICE_ID_ID.to_owned(),
                        }
                    }

                    super_config::DpsAttestationMethod::Tpm { registration_id } => {
                        aziot_identityd_config::DpsAttestationMethod::Tpm { registration_id }
                    }
                };

                aziot_identityd_config::ProvisioningType::Dps {
                    global_endpoint,
                    scope_id: id_scope,
                    attestation,
                }
            }

            super_config::ProvisioningType::None => aziot_identityd_config::ProvisioningType::None,
        };

        aziot_identityd_config::Provisioning {
            always_reprovision_on_startup,
            provisioning,
        }
    };

    let identityd_config = aziot_identityd_config::Settings {
        hostname: if let Some(hostname) = hostname {
            hostname
        } else {
            crate::hostname()?
        },

        homedir: super::AZIOT_IDENTITYD_HOMEDIR_PATH.into(),

        principal: vec![],

        provisioning,

        endpoints: aziot_identityd_config::Endpoints {
            aziot_certd: aziot_certd_endpoint.clone(),
            aziot_identityd: aziot_identityd_endpoint,
            aziot_keyd: aziot_keyd_endpoint.clone(),
            aziot_tpmd: aziot_tpmd_endpoint.clone(),
        },

        localid,
    };

    let preloaded_device_id_pk_bytes = preloaded_device_id_pk.and_then(|preloaded_device_id_pk| {
        let (device_id_pk_uri, preloaded_device_id_pk_bytes) = match preloaded_device_id_pk {
            super_config::SymmetricKey::Inline { value } => (
                aziot_keys_common::PreloadedKeyLocation::Filesystem {
                    path: "/var/secrets/aziot/keyd/device-id".into(),
                },
                Some(value),
            ),

            super_config::SymmetricKey::Preloaded { uri } => (uri, None),
        };

        preloaded_keys.insert(super::DEVICE_ID_ID.to_owned(), device_id_pk_uri);

        preloaded_device_id_pk_bytes
    });

    aziot_keys.insert(
        "homedir_path".to_owned(),
        super::AZIOT_KEYD_HOMEDIR_PATH.to_owned(),
    );

    // Authorization of CS with KS.
    let mut aziotcs_keys = aziot_keyd_config::Principal {
        uid: aziotcs_uid.as_raw(),
        keys: vec![],
    };

    let certd_config = {
        let super_config::CertIssuance { est, local_ca } = cert_issuance;

        let est = if let Some(super_config::Est {
            trusted_certs,
            auth,
            urls,
        }) = est
        {
            let super_config::EstAuth { basic, x509 } = auth;
            let x509 = match x509 {
                Some(super_config::EstAuthX509::BootstrapIdentity {
                    bootstrap_identity_cert,
                    bootstrap_identity_pk,
                }) => {
                    preloaded_certs.insert(
                        super::EST_BOOTSTRAP_ID.to_owned(),
                        aziot_certd_config::PreloadedCert::Uri(bootstrap_identity_cert),
                    );

                    preloaded_keys
                        .insert(super::EST_BOOTSTRAP_ID.to_owned(), bootstrap_identity_pk);
                    aziotcs_keys.keys.push(super::EST_BOOTSTRAP_ID.to_owned());
                    aziotcs_keys.keys.push(super::EST_ID_ID.to_owned());

                    Some(aziot_certd_config::EstAuthX509 {
                        identity: (super::EST_ID_ID.to_owned(), super::EST_ID_ID.to_owned()),
                        bootstrap_identity: Some((
                            super::EST_BOOTSTRAP_ID.to_owned(),
                            super::EST_BOOTSTRAP_ID.to_owned(),
                        )),
                    })
                }

                Some(super_config::EstAuthX509::Identity {
                    identity_cert,
                    identity_pk,
                }) => {
                    preloaded_certs.insert(
                        super::EST_ID_ID.to_owned(),
                        aziot_certd_config::PreloadedCert::Uri(identity_cert),
                    );

                    preloaded_keys.insert(super::EST_ID_ID.to_owned(), identity_pk);
                    aziotcs_keys.keys.push(super::EST_ID_ID.to_owned());

                    Some(aziot_certd_config::EstAuthX509 {
                        identity: (super::EST_ID_ID.to_owned(), super::EST_ID_ID.to_owned()),
                        bootstrap_identity: None,
                    })
                }

                None => None,
            };
            let auth = aziot_certd_config::EstAuth { basic, x509 };

            let trusted_certs = trusted_certs
                .into_iter()
                .enumerate()
                .map(|(i, uri)| {
                    let id = format!("est-server-ca-{}", i + 1);
                    preloaded_certs.insert(id.clone(), aziot_certd_config::PreloadedCert::Uri(uri));
                    id
                })
                .collect();

            Some(aziot_certd_config::Est {
                auth,
                trusted_certs,
                urls,
            })
        } else {
            None
        };

        let local_ca = match local_ca {
            Some(super_config::LocalCa::Issued { cert }) => {
                aziotcs_keys.keys.push(super::LOCAL_CA.to_owned());

                cert_issuance_certs.insert(super::LOCAL_CA.to_owned(), cert);

                Some(aziot_certd_config::LocalCa {
                    cert: super::LOCAL_CA.to_owned(),
                    pk: super::LOCAL_CA.to_owned(),
                })
            }

            Some(super_config::LocalCa::Preloaded { cert, pk }) => {
                preloaded_certs.insert(
                    super::LOCAL_CA.to_owned(),
                    aziot_certd_config::PreloadedCert::Uri(cert),
                );

                preloaded_keys.insert(super::LOCAL_CA.to_owned(), pk);
                aziotcs_keys.keys.push(super::LOCAL_CA.to_owned());

                Some(aziot_certd_config::LocalCa {
                    cert: super::LOCAL_CA.to_owned(),
                    pk: super::LOCAL_CA.to_owned(),
                })
            }

            None => None,
        };

        let mut principal = vec![];
        if !aziotid_certs.certs.is_empty() {
            principal.push(aziotid_certs);
        }

        aziot_certd_config::Config {
            homedir_path: super::AZIOT_CERTD_HOMEDIR_PATH.into(),

            cert_issuance: aziot_certd_config::CertIssuance {
                est,
                local_ca,
                certs: cert_issuance_certs,
            },

            preloaded_certs,

            endpoints: aziot_certd_config::Endpoints {
                aziot_certd: aziot_certd_endpoint,
                aziot_keyd: aziot_keyd_endpoint.clone(),
            },

            principal,
        }
    };

    let keyd_config = {
        let mut principal = vec![aziotid_keys];
        if !aziotcs_keys.keys.is_empty() {
            principal.push(aziotcs_keys);
        }

        aziot_keyd_config::Config {
            aziot_keys,

            preloaded_keys: preloaded_keys
                .into_iter()
                .map(|(id, location)| (id, location.to_string()))
                .collect(),

            endpoints: aziot_keyd_config::Endpoints {
                aziot_keyd: aziot_keyd_endpoint,
            },

            principal,
        }
    };

    let tpmd_config = aziot_tpmd_config::Config {
        endpoints: aziot_tpmd_config::Endpoints {
            aziot_tpmd: aziot_tpmd_endpoint,
        },
    };

    Ok(RunOutput {
        keyd_config,
        certd_config,
        identityd_config,
        tpmd_config,
        preloaded_device_id_pk_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::super_config;

    #[test]
    fn test() {
        let files_directory =
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/test-files/apply"));
        for entry in std::fs::read_dir(files_directory).unwrap() {
            let entry = entry.unwrap();
            if !entry.file_type().unwrap().is_dir() {
                continue;
            }

            let case_directory = entry.path();

            let test_name = case_directory.file_name().unwrap().to_str().unwrap();

            println!(".\n.\n=========\n.\nRunning test {}", test_name);

            let config = std::fs::read(case_directory.join("config.toml")).unwrap();
            let config: super_config::Config =
                toml::from_slice(&config).expect("could not parse config file");

            let expected_keyd_config = std::fs::read(case_directory.join("keyd.toml"))
                .expect("could not deserialize expected aziot-keyd config");
            let expected_certd_config = std::fs::read(case_directory.join("certd.toml"))
                .expect("could not deserialize expected aziot-certd config");
            let expected_identityd_config = std::fs::read(case_directory.join("identityd.toml"))
                .expect("could not deserialize expected aziot-identityd config");
            let expected_tpmd_config = std::fs::read(case_directory.join("tpmd.toml"))
                .expect("could not deserialize expected aziot-tpmd config");

            let expected_preloaded_device_id_pk_bytes =
                match std::fs::read(case_directory.join("device-id")) {
                    Ok(contents) => Some(contents),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                    Err(err) => panic!("could not read device-id file: {}", err),
                };

            let aziotcs_uid = nix::unistd::Uid::from_raw(5555);
            let aziotid_uid = nix::unistd::Uid::from_raw(5557);

            let super::RunOutput {
                keyd_config: actual_keyd_config,
                certd_config: actual_certd_config,
                identityd_config: actual_identityd_config,
                tpmd_config: actual_tpmd_config,
                preloaded_device_id_pk_bytes: actual_preloaded_device_id_pk_bytes,
            } = super::run(config, aziotcs_uid, aziotid_uid).unwrap();

            let actual_keyd_config = toml::to_vec(&actual_keyd_config)
                .expect("could not serialize actual aziot-keyd config");
            let actual_certd_config = toml::to_vec(&actual_certd_config)
                .expect("could not serialize actual aziot-certd config");
            let actual_identityd_config = toml::to_vec(&actual_identityd_config)
                .expect("could not serialize actual aziot-identityd config");
            let actual_tpmd_config = toml::to_vec(&actual_tpmd_config)
                .expect("could not serialize actual aziot-tpmd config");

            // Convert the four configs to bytes::Bytes before asserting, because bytes::Bytes's Debug format prints strings.
            // It doesn't matter for the device ID file since it's binary anyway.
            assert_eq!(
                bytes::Bytes::from(expected_keyd_config),
                bytes::Bytes::from(actual_keyd_config),
                "keyd config does not match"
            );
            assert_eq!(
                bytes::Bytes::from(expected_certd_config),
                bytes::Bytes::from(actual_certd_config),
                "certd config does not match"
            );
            assert_eq!(
                bytes::Bytes::from(expected_identityd_config),
                bytes::Bytes::from(actual_identityd_config),
                "identityd config does not match"
            );
            assert_eq!(
                bytes::Bytes::from(expected_tpmd_config),
                bytes::Bytes::from(actual_tpmd_config),
                "tpmd config does not match"
            );
            assert_eq!(
                expected_preloaded_device_id_pk_bytes, actual_preloaded_device_id_pk_bytes,
                "device ID key bytes do not match"
            );
        }
    }
}
