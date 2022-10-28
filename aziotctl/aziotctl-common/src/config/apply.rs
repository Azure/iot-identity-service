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
        parent_hostname,
        provisioning,
        localid,
        cloud_timeout_sec,
        cloud_retries,
        aziot_max_requests,
        mut aziot_keys,
        mut preloaded_keys,
        cert_issuance,
        mut preloaded_certs,
        tpm,
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

    // Authorization of CS with KS.
    let mut aziotcs_keys = aziot_keyd_config::Principal {
        uid: aziotcs_uid.as_raw(),
        keys: vec![],
    };

    let provisioning = {
        let super_config::Provisioning { provisioning } = provisioning;

        let provisioning = match provisioning {
            super_config::ProvisioningType::Manual {
                inner: super_config::ManualProvisioning::ConnectionString { connection_string },
            } => {
                let (iothub_hostname, device_id, device_id_pk_bytes) =
                    super::parse_manual_connection_string(&connection_string.into_string())
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
                        let csr_subject = match identity {
                            super_config::X509Identity::Issued { identity_cert } => {
                                let auth =
                                    if let super_config::CertIssuanceMethod::Est { url: _, auth } =
                                        &identity_cert.method
                                    {
                                        set_est_auth(
                                            auth.as_ref(),
                                            &mut preloaded_certs,
                                            &mut preloaded_keys,
                                            &mut aziotcs_keys,
                                            super::DEVICE_ID_ID,
                                        )
                                    } else {
                                        None
                                    };

                                aziotid_keys.keys.push(super::DEVICE_ID_ID.to_owned());

                                let issuance_options = into_cert_options(identity_cert, auth);
                                let csr_subject = match &issuance_options.subject {
                                    Some(aziot_certd_config::CertSubject::Subject(entries)) => {
                                        Some(aziot_identityd_config::CsrSubject::Subject {
                                            cn: device_id.clone(),
                                            rest: entries
                                                .iter()
                                                .filter_map(|(k, v)| {
                                                    (!k.eq_ignore_ascii_case("cn"))
                                                        .then(|| (k.to_uppercase(), v.clone()))
                                                })
                                                .collect(),
                                        })
                                    }
                                    _ => None,
                                };
                                cert_issuance_certs
                                    .insert(super::DEVICE_ID_ID.to_owned(), issuance_options);
                                aziotid_certs.certs.push(super::DEVICE_ID_ID.to_owned());
                                csr_subject
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

                                None
                            }
                        };

                        aziot_identityd_config::ManualAuthMethod::X509 {
                            identity_cert: super::DEVICE_ID_ID.to_owned(),
                            identity_pk: super::DEVICE_ID_ID.to_owned(),
                            csr_subject,
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
                payload,
            } => {
                if parent_hostname.is_some() {
                    return Err(anyhow!("DPS provisioning is not supported in nested mode"));
                }

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
                        let (registration_id, auto_renew) = match identity {
                            super_config::X509Identity::Issued { identity_cert } => {
                                let auto_renew = identity_cert.auto_renew.clone();

                                let auth =
                                    if let super_config::CertIssuanceMethod::Est { url: _, auth } =
                                        &identity_cert.method
                                    {
                                        set_est_auth(
                                            auth.as_ref(),
                                            &mut preloaded_certs,
                                            &mut preloaded_keys,
                                            &mut aziotcs_keys,
                                            super::DEVICE_ID_ID,
                                        )
                                    } else {
                                        None
                                    };

                                aziotid_keys.keys.push(super::DEVICE_ID_ID.to_owned());

                                // Identity Service needs authorization to manage temporary credentials
                                // during cert rotation.
                                if let Some(auto_renew) = &auto_renew {
                                    let temp = format!("{}-temp", super::DEVICE_ID_ID);

                                    cert_issuance_certs.insert(
                                        temp.clone(),
                                        into_cert_options(identity_cert.clone(), auth.clone()),
                                    );
                                    aziotid_certs.certs.push(temp.clone());

                                    if auto_renew.rotate_key {
                                        aziotid_keys.keys.push(temp);
                                    }
                                }

                                let issuance_options = into_cert_options(identity_cert, auth);
                                let csr_subject = registration_id
                                    .and_then(|id| {
                                        issuance_options
                                            .subject
                                            .as_ref()
                                            .map(|subject| (id, subject))
                                    })
                                    .map(|(id, subject)| match subject {
                                        aziot_certd_config::CertSubject::CommonName(_) => {
                                            aziot_identityd_config::CsrSubject::CommonName(id)
                                        }
                                        aziot_certd_config::CertSubject::Subject(entries) => {
                                            aziot_identityd_config::CsrSubject::Subject {
                                                cn: id,
                                                rest: entries
                                                    .iter()
                                                    .filter_map(|(k, v)| {
                                                        (!k.eq_ignore_ascii_case("cn"))
                                                            .then(|| (k.to_uppercase(), v.clone()))
                                                    })
                                                    .collect(),
                                            }
                                        }
                                    });
                                cert_issuance_certs
                                    .insert(super::DEVICE_ID_ID.to_owned(), issuance_options);
                                aziotid_certs.certs.push(super::DEVICE_ID_ID.to_owned());

                                (csr_subject, auto_renew)
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

                                (
                                    registration_id
                                        .map(aziot_identityd_config::CsrSubject::CommonName),
                                    None,
                                )
                            }
                        };

                        aziot_identityd_config::DpsAttestationMethod::X509 {
                            registration_id,
                            identity_cert: super::DEVICE_ID_ID.to_owned(),
                            identity_pk: super::DEVICE_ID_ID.to_owned(),
                            identity_auto_renew: auto_renew,
                        }
                    }

                    super_config::DpsAttestationMethod::Tpm { registration_id } => {
                        aziot_identityd_config::DpsAttestationMethod::Tpm { registration_id }
                    }
                };

                let payload = payload.map(|p| aziot_identityd_config::Payload { uri: p.uri });

                aziot_identityd_config::ProvisioningType::Dps {
                    global_endpoint,
                    scope_id: id_scope,
                    attestation,
                    payload,
                }
            }

            super_config::ProvisioningType::None => aziot_identityd_config::ProvisioningType::None,
        };

        aziot_identityd_config::Provisioning {
            provisioning,
            local_gateway_hostname: parent_hostname,
        }
    };

    let identityd_config = aziot_identityd_config::Settings {
        hostname: if let Some(hostname) = hostname {
            hostname
        } else {
            crate::hostname()?
        },

        homedir: super::AZIOT_IDENTITYD_HOMEDIR_PATH.into(),

        max_requests: aziot_max_requests.identityd,

        cloud_timeout_sec,

        cloud_retries,

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

    let certd_config = {
        let super_config::CertIssuance { est, local_ca } = cert_issuance;

        let est = if let Some(super_config::Est {
            trusted_certs,
            identity_auto_renew,
            auth,
            urls,
        }) = est
        {
            let auth = auth.map(|auth| {
                let x509 = match auth.x509 {
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

                        // Certificates Service needs authorization to manage a temporary key
                        // during key rotation.
                        if identity_auto_renew.rotate_key {
                            aziotcs_keys.keys.push(format!("{}-temp", super::EST_ID_ID));
                        }

                        Some(aziot_certd_config::EstAuthX509 {
                            identity: aziot_certd_config::CertificateWithPrivateKey {
                                cert: super::EST_ID_ID.to_owned(),
                                pk: super::EST_ID_ID.to_owned(),
                            },
                            bootstrap_identity: Some(
                                aziot_certd_config::CertificateWithPrivateKey {
                                    cert: super::EST_BOOTSTRAP_ID.to_owned(),
                                    pk: super::EST_BOOTSTRAP_ID.to_owned(),
                                },
                            ),
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
                            identity: aziot_certd_config::CertificateWithPrivateKey {
                                cert: super::EST_ID_ID.to_owned(),
                                pk: super::EST_ID_ID.to_owned(),
                            },
                            bootstrap_identity: None,
                        })
                    }

                    None => None,
                };

                aziot_certd_config::EstAuth {
                    basic: auth.basic,
                    x509,
                }
            });

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
                trusted_certs,
                auth,
                identity_auto_renew,
                urls,
            })
        } else {
            None
        };

        let local_ca = match local_ca {
            Some(super_config::LocalCa::Issued { cert }) => {
                aziotcs_keys.keys.push(super::LOCAL_CA.to_owned());

                cert_issuance_certs
                    .insert(super::LOCAL_CA.to_owned(), into_cert_options(cert, None));

                Some(aziot_certd_config::CertificateWithPrivateKey {
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

                Some(aziot_certd_config::CertificateWithPrivateKey {
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

            max_requests: aziot_max_requests.certd,

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
            max_requests: aziot_max_requests.keyd,

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
        max_requests: aziot_max_requests.tpmd,
        shared: tpm,
        endpoints: aziot_tpmd_config::Endpoints {
            aziot_tpmd: aziot_tpmd_endpoint,
        },
    };

    Ok(RunOutput {
        certd_config,
        identityd_config,
        keyd_config,
        tpmd_config,
        preloaded_device_id_pk_bytes,
    })
}

fn into_cert_options(
    opts: super_config::CertIssuanceOptions,
    auth: Option<aziot_certd_config::EstAuth>,
) -> aziot_certd_config::CertIssuanceOptions {
    let method = match opts.method {
        super_config::CertIssuanceMethod::Est { url, .. } => {
            aziot_certd_config::CertIssuanceMethod::Est { url, auth }
        }
        super_config::CertIssuanceMethod::LocalCa => {
            aziot_certd_config::CertIssuanceMethod::LocalCa
        }
        super_config::CertIssuanceMethod::SelfSigned => {
            aziot_certd_config::CertIssuanceMethod::SelfSigned
        }
    };

    aziot_certd_config::CertIssuanceOptions {
        method,
        expiry_days: opts.expiry_days,
        subject: opts.subject,
    }
}

pub fn set_est_auth(
    auth: Option<&super_config::EstAuth>,
    preloaded_certs: &mut std::collections::BTreeMap<String, aziot_certd_config::PreloadedCert>,
    preloaded_keys: &mut std::collections::BTreeMap<
        String,
        aziot_keys_common::PreloadedKeyLocation,
    >,
    aziotcs_keys: &mut aziot_keyd_config::Principal,
    cert_name: &str,
) -> Option<aziot_certd_config::EstAuth> {
    auth.map(|auth| {
        let auth_x509 = auth.x509.as_ref().map(|x509| {
            let identity_cert_id = format!("{}-{}", super::EST_ID_ID, cert_name);

            let bootstrap_identity = match x509 {
                super_config::EstAuthX509::BootstrapIdentity {
                    bootstrap_identity_cert,
                    bootstrap_identity_pk,
                } => {
                    let bootstrap_cert_id = format!("{}-{}", super::EST_BOOTSTRAP_ID, cert_name);

                    let bootstrap_identity_cert =
                        aziot_certd_config::PreloadedCert::Uri(bootstrap_identity_cert.clone());
                    preloaded_certs.insert(bootstrap_cert_id.clone(), bootstrap_identity_cert);

                    preloaded_keys.insert(bootstrap_cert_id.clone(), bootstrap_identity_pk.clone());
                    aziotcs_keys.keys.push(bootstrap_cert_id.clone());

                    // Certificates Service needs authorization to manage a temporary key
                    // during key rotation.
                    aziotcs_keys.keys.push(format!("{}-temp", identity_cert_id));

                    Some(aziot_certd_config::CertificateWithPrivateKey {
                        cert: bootstrap_cert_id.clone(),
                        pk: bootstrap_cert_id,
                    })
                }

                super_config::EstAuthX509::Identity {
                    identity_cert,
                    identity_pk,
                } => {
                    let identity_cert =
                        aziot_certd_config::PreloadedCert::Uri(identity_cert.clone());
                    preloaded_certs.insert(identity_cert_id.clone(), identity_cert);

                    preloaded_keys.insert(identity_cert_id.clone(), identity_pk.clone());

                    None
                }
            };

            aziotcs_keys.keys.push(identity_cert_id.clone());

            aziot_certd_config::EstAuthX509 {
                identity: aziot_certd_config::CertificateWithPrivateKey {
                    cert: identity_cert_id.clone(),
                    pk: identity_cert_id,
                },
                bootstrap_identity,
            }
        });

        aziot_certd_config::EstAuth {
            basic: auth.basic.clone(),
            x509: auth_x509,
        }
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
            let aziotid_uid = nix::unistd::Uid::from_raw(5556);

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

    #[test]
    #[should_panic(expected = "DPS provisioning is not supported in nested mode")]
    fn dps_not_supported_in_nested() {
        let super_config = r#"
local_gateway_hostname = "device.hostname"

[provisioning]
source = "dps"
global_endpoint = "https://global.azure-devices-provisioning.net/"
id_scope = "0ab1234C5D6"

[provisioning.attestation]
method = "symmetric_key"
registration_id = "my-device"
symmetric_key = { value = "YXppb3QtaWRlbnRpdHktc2VydmljZXxhemlvdC1pZGVudGl0eS1zZXJ2aWNlfGF6aW90LWlkZW50aXR5LXNlcg==" }

"#;
        let super_config: super_config::Config = toml::from_str(super_config).unwrap();

        let aziotcs_uid = nix::unistd::Uid::from_raw(5555);
        let aziotid_uid = nix::unistd::Uid::from_raw(5556);

        super::run(super_config, aziotcs_uid, aziotid_uid).unwrap();
    }
}
