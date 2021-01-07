// Copyright (c) Microsoft. All rights reserved.

//! This subcommand interactively asks the user to give out basic provisioning information for their device and
//! creates the config files for the four services based on that information.
//!
//! Notes:
//!
//! - Provisioning with a symmetric key (manual or DPS) requires the key to be preloaded into KS, which means it needs to be
//!   saved to a file. This subcommand uses a file named `/var/secrets/aziot/keyd/device-id` for that purpose.
//!   It creates the directory structure and ACLs the directory and the file appropriately to the KS user.
//!
//! - `always_reprovisioning_on_startup` is enabled by default in IS provisioning settings.
//!
//! - This implementation assumes that Microsoft's implementation of libaziot-keys is being used, in that it generates the keyd config
//!   with the `aziot_keys.homedir_path` property set, and with validation that the preloaded keys must be `file://` or `pkcs11:` URIs.

use anyhow::{anyhow, Context, Result};

const DPS_GLOBAL_ENDPOINT: &str = "https://global.azure-devices-provisioning.net";

const AZIOT_KEYD_HOMEDIR_PATH: &str = "/var/lib/aziot/keyd";
const AZIOT_CERTD_HOMEDIR_PATH: &str = "/var/lib/aziot/certd";
const AZIOT_IDENTITYD_HOMEDIR_PATH: &str = "/var/lib/aziot/identityd";

/// The ID used for the device ID key (symmetric or X.509 private) and the device ID cert.
const DEVICE_ID_ID: &str = "device-id";

/// The ID used for the private key and cert that is used as the local CA.
const LOCAL_CA: &str = "local-ca";

/// The ID used for the private key and cert that is used as the client cert to authenticate with the EST server.
const EST_ID_ID: &str = "est-id";

/// The ID used for the private key and cert that is used as the client cert to authenticate with the EST server for the initial bootstrap.
const EST_BOOTSTRAP_ID: &str = "est-bootstrap-id";

/// The ID used for the CA cert that is used to validate the EST server's server cert.
const EST_SERVER_CA_ID: &str = "est-server-ca";

pub(crate) fn run() -> Result<()> {
    // In production, running as root is the easiest way to guarantee the tool has write access to every service's config file.
    // But it's convenient to not do this for the sake of development because the the development machine doesn't necessarily
    // have the package installed and the users created, and it's easier to have the config files owned by the current user anyway.
    //
    // So when running as root, get the four users appropriately.
    // Otherwise, if this is a debug build, fall back to using the current user.
    // Otherwise, tell the user to re-run as root.
    let (aziotks_user, aziotcs_user, aziotid_user, aziottpm_user) =
        if nix::unistd::Uid::current().is_root() {
            let aziotks_user = nix::unistd::User::from_name("aziotks")
                .context("could not query aziotks user information")?
                .ok_or_else(|| anyhow!("could not query aziotks user information"))?;

            let aziotcs_user = nix::unistd::User::from_name("aziotcs")
                .context("could not query aziotcs user information")?
                .ok_or_else(|| anyhow!("could not query aziotcs user information"))?;

            let aziotid_user = nix::unistd::User::from_name("aziotid")
                .context("could not query aziotid user information")?
                .ok_or_else(|| anyhow!("could not query aziotid user information"))?;

            let aziottpm_user = nix::unistd::User::from_name("aziottpm")
                .context("could not query aziottpm user information")?
                .ok_or_else(|| anyhow!("could not query aziottpm user information"))?;

            (aziotks_user, aziotcs_user, aziotid_user, aziottpm_user)
        } else if cfg!(debug_assertions) {
            let current_user = nix::unistd::User::from_uid(nix::unistd::Uid::current())
                .context("could not query current user information")?
                .ok_or_else(|| anyhow!("could not query current user information"))?;
            (
                current_user.clone(),
                current_user.clone(),
                current_user.clone(),
                current_user,
            )
        } else {
            return Err(anyhow!("this command must be run as root"));
        };

    for &f in &[
        "/etc/aziot/certd/config.toml",
        "/etc/aziot/identityd/config.toml",
        "/etc/aziot/keyd/config.toml",
        "/etc/aziot/tpmd/config.toml",
    ] {
        // Don't overwrite any of the configs if they already exist.
        //
        // It would be less racy to test this right before we're about to overwrite the files, but by then we'll have asked the user
        // all of the questions and it would be a waste to give up.
        if std::path::Path::new(f).exists() {
            return Err(anyhow!(
                    "\
                    Cannot run because file {} already exists. \
                    Delete this file (after taking a backup if necessary) before running this command.\
                ",
                f
            ));
        }
    }

    let mut stdin = Stdin {
        editor: rustyline::Editor::new(),
    };
    stdin.editor.set_helper(Some(StdinHelper {
        reading_secret: false,
    }));

    let RunOutput {
        keyd_config,
        certd_config,
        identityd_config,
        tpmd_config,
        preloaded_device_id_pk_bytes,
    } = run_inner(&mut stdin)?;

    if let Some(preloaded_device_id_pk_bytes) = preloaded_device_id_pk_bytes {
        println!("Note: Symmetric key will be written to /var/secrets/aziot/keyd/device-id");

        create_dir_all("/var/secrets/aziot/keyd", &aziotks_user, 0o0700)?;
        write_file(
            "/var/secrets/aziot/keyd/device-id",
            &preloaded_device_id_pk_bytes,
            &aziotks_user,
            0o0600,
        )?;
    }

    write_file(
        "/etc/aziot/keyd/config.toml",
        &keyd_config,
        &aziotks_user,
        0o0600,
    )?;

    write_file(
        "/etc/aziot/certd/config.toml",
        &certd_config,
        &aziotcs_user,
        0o0600,
    )?;

    write_file(
        "/etc/aziot/identityd/config.toml",
        &identityd_config,
        &aziotid_user,
        0o0600,
    )?;

    write_file(
        "/etc/aziot/tpmd/config.toml",
        &tpmd_config,
        &aziottpm_user,
        0o0600,
    )?;

    println!("aziot-identity-service has been configured successfully!");
    println!(
        "You can find the configured files at /etc/aziot/{{key,cert,identity,tpm}}d/config.toml"
    );

    Ok(())
}

/// This macro expands to a relatively straightforward expression. The advantage of using this macro instead of calling
/// [`choose`] directly is that the macro forces you to use each one of your choice enum variants exactly once, no more and no less.
macro_rules! choose {
    (
        $stdin:ident ,
        $question:expr ,
        $($choice:path => $value:expr ,)*
    ) => {{
        match choose($stdin, $question, &[$($choice ,)*])? {
            $($choice => $value ,)*
        }
    }};
}

#[derive(Debug)]
struct RunOutput {
    certd_config: Vec<u8>,
    identityd_config: Vec<u8>,
    keyd_config: Vec<u8>,
    tpmd_config: Vec<u8>,
    preloaded_device_id_pk_bytes: Option<Vec<u8>>,
}

/// Returns the KS/CS/IS configs, and optionally the contents of a new /var/secrets/aziot/keyd/device-id file to hold the device ID symmetric key.
fn run_inner(stdin: &mut impl Reader) -> Result<RunOutput> {
    println!("Welcome to the configuration tool for aziot-identity-service.");
    println!();
    println!("This command will set up the configurations for aziot-keyd, aziot-certd and aziot-identityd.");
    println!();

    let hostname = crate::internal::common::get_hostname()?;

    let (provisioning_type, preloaded_device_id_pk_bytes) = choose! {
        stdin,
        "What kind of authentication method should this device use?",

        ProvisioningMethod::ManualConnectionString => {
            let (iothub_hostname, device_id, symmetric_key) = loop {
                let connection_string = prompt(stdin, "Enter the connection string.")?;
                match parse_manual_connection_string(&connection_string) {
                    Ok(parts) => break parts,
                    Err(err) => println!("Connection string is invalid: {}", err),
                }
            };

            (
                aziot_identityd_config::ProvisioningType::Manual {
                    iothub_hostname,
                    device_id,
                    authentication: aziot_identityd_config::ManualAuthMethod::SharedPrivateKey {
                        device_id_pk: DEVICE_ID_ID.to_owned(),
                    },
                },
                Some(symmetric_key),
            )
        },

        ProvisioningMethod::ManualSymmetricKey => {
            let iothub_hostname = prompt(stdin, "Enter the IoT Hub hostname.")?;
            let device_id = prompt(stdin, "Enter the device ID.")?;
            let symmetric_key = loop {
                let symmetric_key = prompt_secret(stdin, "Enter the device symmetric key (in its original base64 form).")?;
                match base64::decode(symmetric_key) {
                    Ok(symmetric_key) => break symmetric_key,
                    Err(err) => println!(r#"Symmetric key could not be decoded from base64: {}"#, err),
                }
            };

            (
                aziot_identityd_config::ProvisioningType::Manual {
                    iothub_hostname,
                    device_id,
                    authentication: aziot_identityd_config::ManualAuthMethod::SharedPrivateKey {
                        device_id_pk: DEVICE_ID_ID.to_owned(),
                    },
                },
                Some(symmetric_key),
            )
        },

        ProvisioningMethod::ManualX509 => {
            let iothub_hostname = prompt(stdin, "Enter the IoT Hub hostname.")?;
            let device_id = prompt(stdin, "Enter the IoT Device ID.")?;

            (
                aziot_identityd_config::ProvisioningType::Manual {
                    iothub_hostname,
                    device_id,
                    authentication: aziot_identityd_config::ManualAuthMethod::X509 {
                        identity_cert: DEVICE_ID_ID.to_owned(),
                        identity_pk: DEVICE_ID_ID.to_owned(),
                    },
                },
                None,
            )
        },

        ProvisioningMethod::DpsSymmetricKey => {
            let scope_id = prompt(stdin, "Enter the DPS ID scope.")?;
            let registration_id = prompt(stdin, "Enter the DPS registration ID.")?;
            let symmetric_key = loop {
                let symmetric_key = prompt_secret(stdin, "Enter the DPS symmetric key (in its original base64 form).")?;
                match base64::decode(symmetric_key) {
                    Ok(symmetric_key) => break symmetric_key,
                    Err(err) => println!(r#"Symmetric key could not be decoded from base64: {}"#, err),
                }
            };

            (
                aziot_identityd_config::ProvisioningType::Dps {
                    global_endpoint: DPS_GLOBAL_ENDPOINT.to_owned(),
                    scope_id,
                    attestation: aziot_identityd_config::DpsAttestationMethod::SymmetricKey {
                        registration_id,
                        symmetric_key: DEVICE_ID_ID.to_owned(),
                    },
                },
                Some(symmetric_key),
            )
        },

        ProvisioningMethod::DpsX509 => {
            let scope_id = prompt(stdin, "Enter the DPS ID scope.")?;
            let registration_id = prompt(stdin, "Enter the DPS registration ID.")?;

            (
                aziot_identityd_config::ProvisioningType::Dps {
                    global_endpoint: DPS_GLOBAL_ENDPOINT.to_owned(),
                    scope_id,
                    attestation: aziot_identityd_config::DpsAttestationMethod::X509 {
                        registration_id,
                        identity_cert: DEVICE_ID_ID.to_owned(),
                        identity_pk: DEVICE_ID_ID.to_owned(),
                    },
                },
                None,
            )
        },

        ProvisioningMethod::Tpm => {
            let scope_id = prompt(stdin, "Enter the DPS ID scope.")?;
            let registration_id = prompt(stdin, "Enter the DPS registration ID.")?;

            (
                aziot_identityd_config::ProvisioningType::Dps {
                    global_endpoint: DPS_GLOBAL_ENDPOINT.to_owned(),
                    scope_id,
                    attestation: aziot_identityd_config::DpsAttestationMethod::Tpm {
                        registration_id,
                    },
                },
                None,
            )
        },
    };

    let uses_pkcs11 = choose! {
        stdin,
        "Does this device use an HSM via a PKCS#11 library?",

        YesNo::Yes => true,
        YesNo::No => false,
    };

    let mut device_id_source = None;

    // Might be mutated again while building certd config to insert EST ID cert's private key
    let mut keyd_config = {
        let mut keyd_config = aziot_keyd_config::Config {
            aziot_keys: Default::default(),
            preloaded_keys: Default::default(),
            endpoints: Default::default(),
        };

        keyd_config.aziot_keys.insert(
            "homedir_path".to_owned(),
            AZIOT_KEYD_HOMEDIR_PATH.to_owned(),
        );

        if uses_pkcs11 {
            let pkcs11_lib_path = prompt(stdin, "Enter the path of the PKCS#11 library.")?;
            let pkcs11_base_slot = prompt(stdin, "Enter the PKCS#11 URI of a slot in the HSM that will be used for storing new keys at runtime.")?;
            keyd_config
                .aziot_keys
                .insert("pkcs11_lib_path".to_owned(), pkcs11_lib_path);
            keyd_config
                .aziot_keys
                .insert("pkcs11_base_slot".to_owned(), pkcs11_base_slot);
        }

        if preloaded_device_id_pk_bytes.is_some() {
            let device_id_pk_uri = aziot_keys_common::PreloadedKeyLocation::Filesystem {
                path: "/var/secrets/aziot/keyd/device-id".into(),
            };
            keyd_config
                .preloaded_keys
                .insert(DEVICE_ID_ID.to_owned(), device_id_pk_uri.to_string());
        } else if matches!(
            provisioning_type,
            aziot_identityd_config::ProvisioningType::Manual {
                authentication: aziot_identityd_config::ManualAuthMethod::X509 { .. },
                ..
            } | aziot_identityd_config::ProvisioningType::Dps {
                attestation: aziot_identityd_config::DpsAttestationMethod::X509 { .. },
                ..
            }
        ) {
            device_id_source = Some(choose! {
                stdin,
                "Where is your your device identity certificate and private key?",

                DeviceIdSource::Preloaded => {
                    let prompt_question =
                        if uses_pkcs11 {
                            "Enter the PKCS#11 URI or filesystem path of the device ID certificate's private key file."
                        }
                        else {
                            "Enter the filesystem path of the device ID certificate's private key file."
                        };
                    let device_id_pk_uri = loop {
                        let device_id_pk_uri = prompt(stdin, prompt_question)?;
                        if let Some(device_id_pk_uri) = parse_preloaded_key_location(&device_id_pk_uri) {
                            break device_id_pk_uri;
                        }
                    };
                    keyd_config.preloaded_keys.insert(DEVICE_ID_ID.to_owned(), device_id_pk_uri.to_string());

                    DeviceIdSource::Preloaded
                },

                DeviceIdSource::LocalCa => {
                    let prompt_question =
                        if uses_pkcs11 {
                            "Enter the PKCS#11 URI or filesystem path of the CA certificate's private key file."
                        }
                        else {
                            "Enter the filesystem path of the CA certificate's private key file."
                        };
                    let local_ca_pk_uri = loop {
                        let local_ca_pk_uri = prompt(stdin, prompt_question)?;
                        if let Some(local_ca_pk_uri) = parse_preloaded_key_location(&local_ca_pk_uri) {
                            break local_ca_pk_uri;
                        }
                    };
                    keyd_config.preloaded_keys.insert(LOCAL_CA.to_owned(), local_ca_pk_uri.to_string());

                    DeviceIdSource::LocalCa
                },

                DeviceIdSource::Est => DeviceIdSource::Est,
            });
        }

        keyd_config
    };

    let certd_config = {
        let mut certd_config = aziot_certd_config::Config {
            homedir_path: AZIOT_CERTD_HOMEDIR_PATH.into(),
            cert_issuance: Default::default(),
            preloaded_certs: Default::default(),
            endpoints: Default::default(),
        };

        match device_id_source {
            Some(DeviceIdSource::Preloaded) => {
                let device_id_cert_uri = loop {
                    let device_id_cert_uri = prompt(
                        stdin,
                        "Enter the filesystem path of the device ID certificate file.",
                    )?;
                    if let Some(device_id_cert_uri) = parse_cert_location(&device_id_cert_uri) {
                        break device_id_cert_uri;
                    }
                };
                let device_id_cert_uri = aziot_certd_config::PreloadedCert::Uri(device_id_cert_uri);
                certd_config
                    .preloaded_certs
                    .insert(DEVICE_ID_ID.to_owned(), device_id_cert_uri);
            }

            Some(DeviceIdSource::LocalCa) => {
                let local_ca_cert_uri = loop {
                    let local_ca_cert_uri = prompt(
                        stdin,
                        "Enter the filesystem path of the CA certificate file.",
                    )?;
                    if let Some(local_ca_cert_uri) = parse_cert_location(&local_ca_cert_uri) {
                        break local_ca_cert_uri;
                    }
                };
                let local_ca_cert_uri = aziot_certd_config::PreloadedCert::Uri(local_ca_cert_uri);
                certd_config
                    .preloaded_certs
                    .insert(LOCAL_CA.to_owned(), local_ca_cert_uri);

                certd_config.cert_issuance.local_ca = Some(aziot_certd_config::LocalCa {
                    cert: LOCAL_CA.to_owned(),
                    pk: LOCAL_CA.to_owned(),
                });

                certd_config.cert_issuance.certs.insert(
                    DEVICE_ID_ID.to_owned(),
                    aziot_certd_config::CertIssuanceOptions {
                        method: aziot_certd_config::CertIssuanceMethod::LocalCa,
                        common_name: Some(hostname.clone()),
                        expiry_days: None,
                    },
                );
            }

            Some(DeviceIdSource::Est) => {
                certd_config.cert_issuance.certs.insert(
                    DEVICE_ID_ID.to_owned(),
                    aziot_certd_config::CertIssuanceOptions {
                        method: aziot_certd_config::CertIssuanceMethod::Est,
                        common_name: Some(hostname.clone()),
                        expiry_days: None,
                    },
                );

                let urls = {
                    let mut urls: std::collections::BTreeMap<_, _> = Default::default();

                    let default_url = read_est_url(stdin, "Enter the URL of your EST server.")?;
                    urls.insert("default".to_owned(), default_url);

                    choose! {
                        stdin,
                        "Do you have a separate URL for issuing device identity certificates from your EST server?",

                        YesNo::Yes => {
                            let device_id_url =
                                read_est_url(
                                    stdin,
                                    "Enter the URL of your EST server that should be used for issuing device identity certificates.",
                                )?;
                            urls.insert(DEVICE_ID_ID.to_owned(), device_id_url);
                        },

                        YesNo::No => (),
                    };

                    urls
                };

                let trusted_certs = choose! {
                    stdin,
                    "Does your EST server need a specific CA certificate to validate its certificate?",

                    EstTrustedCert::Os => vec![],

                    EstTrustedCert::Separate => {
                        let est_trusted_cert_uri = loop {
                            let est_trusted_cert_uri = prompt(stdin, "Enter the filesystem path of the CA certificate that should be used to validate your EST server's server certificate file.")?;
                            if let Some(est_trusted_cert_uri) = parse_cert_location(&est_trusted_cert_uri) {
                                break est_trusted_cert_uri;
                            }
                        };
                        let est_trusted_cert_uri = aziot_certd_config::PreloadedCert::Uri(est_trusted_cert_uri);
                        certd_config.preloaded_certs.insert(EST_SERVER_CA_ID.to_owned(), est_trusted_cert_uri);

                        vec![EST_SERVER_CA_ID.to_owned()]
                    },
                };

                let est_auth_basic = choose! {
                    stdin,
                    "Does your EST server use a username and password for authentication?",

                    YesNo::Yes => {
                        let username = prompt(stdin, "Enter the username used to authenticate with your EST server.")?;
                        let password = prompt_secret(stdin, "Enter the password used to authenticate with your EST server.")?;
                        Some(aziot_certd_config::EstAuthBasic {
                            username,
                            password,
                        })
                    },

                    YesNo::No => None,
                };

                let est_auth_x509 = choose! {
                    stdin,
                    "Does your EST server use a client certificate for authentication?",

                    YesNo::Yes => choose! {
                        stdin,
                        "Where is the client certificate that should be used to authenticate with your EST server?",

                        EstIdSource::Preloaded => {
                            let prompt_question =
                                if uses_pkcs11 {
                                    "Enter the PKCS#11 URI or filesystem path of the EST ID certificate's private key file."
                                }
                                else {
                                    "Enter the filesystem path of the EST ID certificate's private key file."
                                };
                            let est_id_pk_uri = loop {
                                let est_id_pk_uri = prompt(stdin, prompt_question)?;
                                if let Some(est_id_pk_uri) = parse_preloaded_key_location(&est_id_pk_uri) {
                                    break est_id_pk_uri;
                                }
                            };
                            keyd_config.preloaded_keys.insert(EST_ID_ID.to_owned(), est_id_pk_uri.to_string());

                            let est_id_cert_uri = loop {
                                let est_id_cert_uri = prompt(stdin, "Enter the filesystem path of the EST ID certificate file.")?;
                                if let Some(est_id_cert_uri) = parse_cert_location(&est_id_cert_uri) {
                                    break est_id_cert_uri;
                                }
                            };
                            let est_id_cert_uri = aziot_certd_config::PreloadedCert::Uri(est_id_cert_uri);
                            certd_config.preloaded_certs.insert(EST_ID_ID.to_owned(), est_id_cert_uri);

                            Some(aziot_certd_config::EstAuthX509 {
                                identity: (EST_ID_ID.to_owned(), EST_ID_ID.to_owned()),
                                bootstrap_identity: None,
                            })
                        },

                        EstIdSource::Bootstrap => {
                            let prompt_question =
                                if uses_pkcs11 {
                                    "Enter the PKCS#11 URI or filesystem path of the EST bootstrap ID certificate's private key file."
                                }
                                else {
                                    "Enter the filesystem path of the EST bootstrap ID certificate's private key file."
                                };
                            let est_bootstrap_id_pk_uri = loop {
                                let est_bootstrap_id_pk_uri = prompt(stdin, prompt_question)?;
                                if let Some(est_bootstrap_id_pk_uri) = parse_preloaded_key_location(&est_bootstrap_id_pk_uri) {
                                    break est_bootstrap_id_pk_uri;
                                }
                            };
                            keyd_config.preloaded_keys.insert(EST_BOOTSTRAP_ID.to_owned(), est_bootstrap_id_pk_uri.to_string());

                            let est_bootstrap_id_cert_uri = loop {
                                let est_bootstrap_id_cert_uri = prompt(stdin, "Enter the filesystem path of the EST bootstrap ID certificate file.")?;
                                if let Some(est_bootstrap_id_cert_uri) = parse_cert_location(&est_bootstrap_id_cert_uri) {
                                    break est_bootstrap_id_cert_uri;
                                }
                            };
                            let est_bootstrap_id_cert_uri = aziot_certd_config::PreloadedCert::Uri(est_bootstrap_id_cert_uri);
                            certd_config.preloaded_certs.insert(EST_BOOTSTRAP_ID.to_owned(), est_bootstrap_id_cert_uri);

                            Some(aziot_certd_config::EstAuthX509 {
                                identity: (EST_ID_ID.to_owned(), EST_ID_ID.to_owned()),
                                bootstrap_identity: Some((EST_BOOTSTRAP_ID.to_owned(), EST_BOOTSTRAP_ID.to_owned())),
                            })
                        },
                    },

                    YesNo::No => None,
                };

                certd_config.cert_issuance.est = Some(aziot_certd_config::Est {
                    auth: aziot_certd_config::EstAuth {
                        basic: est_auth_basic,
                        x509: est_auth_x509,
                    },

                    trusted_certs,

                    urls,
                });
            }

            None => (),
        }

        certd_config
    };

    let tpmd_config = aziot_tpmd_config::Config {
        endpoints: Default::default(),
    };

    let keyd_config =
        toml::to_vec(&keyd_config).context("could not serialize aziot-keyd config")?;
    let certd_config =
        toml::to_vec(&certd_config).context("could not serialize aziot-certd config")?;

    let identityd_config = {
        aziot_identityd_config::Settings {
            hostname,
            homedir: AZIOT_IDENTITYD_HOMEDIR_PATH.into(),
            principal: vec![],
            provisioning: aziot_identityd_config::Provisioning {
                always_reprovisioning_on_startup: true,
                provisioning: provisioning_type,
            },
            endpoints: Default::default(),
            localid: None,
        }
    };
    let identityd_config =
        toml::to_vec(&identityd_config).context("could not serialize aziot-identityd config")?;

    let tpmd_config =
        toml::to_vec(&tpmd_config).context("could not serialize aziot-certd config")?;

    Ok(RunOutput {
        keyd_config,
        certd_config,
        identityd_config,
        tpmd_config,
        preloaded_device_id_pk_bytes,
    })
}

#[derive(Clone, Copy, Debug, derive_more::Display)]
enum YesNo {
    #[display(fmt = "Yes")]
    Yes,

    #[display(fmt = "No")]
    No,
}

#[derive(Clone, Copy, Debug, derive_more::Display)]
enum ProvisioningMethod {
    #[display(fmt = "Manual provisioning with connection string (symmetric key only)")]
    ManualConnectionString,

    #[display(fmt = "Manual provisioning with symmetric key")]
    ManualSymmetricKey,

    #[display(
        fmt = "Manual provisioning with device identity certificate (self-signed or CA-signed)"
    )]
    ManualX509,

    #[display(fmt = "DPS provisioning with symmetric key")]
    DpsSymmetricKey,

    #[display(
        fmt = "DPS provisioning with device identity certificate (self-signed or CA-signed)"
    )]
    DpsX509,

    #[display(fmt = "DPS provisioning with TPM")]
    Tpm,
}

#[derive(Clone, Copy, Debug, derive_more::Display)]
enum DeviceIdSource {
    #[display(fmt = "Stored on the filesystem")]
    Preloaded,

    #[display(fmt = "Issued dynamically from a CA cert stored on the filesystem")]
    LocalCa,

    #[display(fmt = "Issued dynamically from an EST server")]
    Est,
}

#[derive(Clone, Copy, Debug, derive_more::Display)]
enum EstIdSource {
    #[display(fmt = "Stored on the filesystem (an \"EST ID\" certificate)")]
    Preloaded,

    #[display(
        fmt = "Issued dynamically from the EST server using a different client certificate (a \"bootstrap EST ID\" certificate)"
    )]
    Bootstrap,
}

#[derive(Clone, Copy, Debug, derive_more::Display)]
enum EstTrustedCert {
    #[display(
        fmt = "My EST server's server certificate can be validated with just the CA certificates already installed on my OS"
    )]
    Os,

    #[display(
        fmt = "My EST server's server certificate can only be validated with a separate CA certificate."
    )]
    Separate,
}

/// This trait exists to read lines from stdin without directly using `std::io::StdinLock`,
/// because reading secrets (symmetric keys, etc) requires disabling echo on the tty directly which can't be done while stdin is locked.
///
/// Making a trait also allows it to be mocked for tests where the input comes from files.
trait Reader {
    /// Prints the given prompt string, reads a line from the user and appends the response to the given line buffer.
    ///
    /// Unlike `std::io::BufRead::read_line`, this does not include a trailing newline. Specifically, empty input is returned as an empty string.
    /// EOF is indicated by returning a `Err(std::io::ErrorKind::UnexpectedEof)` instead.
    fn read_line(&mut self, prompt: &str, line: &mut String) -> std::io::Result<usize>;

    /// Prints the given prompt string, reads a secret from the user and appends the response to the given line buffer.
    ///
    /// Unlike `std::io::BufRead::read_line`, this does not include a trailing newline. Specifically, empty input is returned as an empty string.
    /// EOF is indicated by returning a `Err(std::io::ErrorKind::UnexpectedEof)` instead.
    fn read_secret(&mut self, prompt: &str, line: &mut String) -> std::io::Result<usize>;
}

struct Stdin {
    editor: rustyline::Editor<StdinHelper>,
}

impl Reader for Stdin {
    fn read_line(&mut self, prompt: &str, line: &mut String) -> std::io::Result<usize> {
        self.editor
            .helper_mut()
            .expect("helper is always Some")
            .reading_secret = false;

        loop {
            match self.editor.readline(prompt) {
                Ok(response) => {
                    line.push_str(&response);
                    return Ok(response.len());
                }

                Err(rustyline::error::ReadlineError::Io(err)) => return Err(err),

                Err(rustyline::error::ReadlineError::Eof)
                | Err(rustyline::error::ReadlineError::Interrupted) => {
                    return Err(std::io::ErrorKind::UnexpectedEof.into())
                }

                Err(rustyline::error::ReadlineError::Utf8Error) => {
                    println!("Input could not be parsed as UTF-8")
                }

                Err(rustyline::error::ReadlineError::Errno(err)) => {
                    return Err(std::io::Error::new(std::io::ErrorKind::Other, err))
                }

                Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, err)),
            }
        }
    }

    fn read_secret(&mut self, prompt: &str, line: &mut String) -> std::io::Result<usize> {
        self.editor
            .helper_mut()
            .expect("helper is always Some")
            .reading_secret = true;

        match self.editor.readline(prompt) {
            Ok(response) => {
                line.push_str(&response);
                Ok(response.len())
            }

            Err(rustyline::error::ReadlineError::Io(err)) => Err(err),

            Err(rustyline::error::ReadlineError::Eof)
            | Err(rustyline::error::ReadlineError::Interrupted) => {
                Err(std::io::ErrorKind::UnexpectedEof.into())
            }

            Err(rustyline::error::ReadlineError::Utf8Error) => Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Input could not be parsed as UTF-8",
            )),

            Err(rustyline::error::ReadlineError::Errno(err)) => {
                Err(std::io::Error::new(std::io::ErrorKind::Other, err))
            }

            Err(err) => Err(std::io::Error::new(std::io::ErrorKind::Other, err)),
        }
    }
}

/// This is an impl of `rustyline::Helper` for use with the `rustyline::Editor`.
///
/// rustyline uses a "highlighter" to override the text the user types. Its primary goal is syntax highlighting.
/// We use ours to mask the input of secrets.
///
/// Ref: <https://github.com/kkawakam/rustyline/blob/v6.3.0/examples/read_password.rs>
struct StdinHelper {
    reading_secret: bool,
}

impl rustyline::completion::Completer for StdinHelper {
    type Candidate = <() as rustyline::completion::Completer>::Candidate;
}

impl rustyline::hint::Hinter for StdinHelper {}

impl rustyline::highlight::Highlighter for StdinHelper {
    fn highlight<'l>(&self, line: &'l str, _pos: usize) -> std::borrow::Cow<'l, str> {
        if self.reading_secret {
            std::borrow::Cow::Owned("*".repeat(line.len()))
        } else {
            std::borrow::Cow::Borrowed(line)
        }
    }

    fn highlight_char(&self, _line: &str, _pos: usize) -> bool {
        self.reading_secret
    }
}

impl rustyline::validate::Validator for StdinHelper {}

impl rustyline::Helper for StdinHelper {}

fn choose<'a, TChoice>(
    stdin: &mut impl Reader,
    question: &str,
    choices: &'a [TChoice],
) -> Result<&'a TChoice>
where
    TChoice: std::fmt::Display,
{
    println!("{}", question);

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]
    let max_choice_width = (choices.len() as f64).log10() as usize + 1;

    println!();
    for (i, choice) in choices.iter().enumerate() {
        println!(
            "{:>max_choice_width$}: {}",
            i + 1,
            choice,
            max_choice_width = max_choice_width
        );
    }
    println!();

    let prompt_question = format!("Enter a choice [1-{}]", choices.len());

    loop {
        let answer = prompt(stdin, &prompt_question)?;
        let answer = answer
            .parse()
            .ok()
            .and_then(|choice: usize| choice.checked_sub(1))
            .and_then(|choice| choices.get(choice));
        if let Some(answer) = answer {
            return Ok(answer);
        }

        println!("Invalid choice.");
    }
}

fn prompt(stdin: &mut impl Reader, question: &str) -> Result<String> {
    println!("{}", question);

    let mut line = String::new();

    loop {
        stdin.read_line("> ", &mut line)?;
        if line.is_empty() {
            continue;
        }

        println!();

        return Ok(line);
    }
}

fn prompt_secret(stdin: &mut impl Reader, question: &str) -> Result<String> {
    println!("{}", question);

    let mut line = String::new();

    loop {
        stdin.read_secret("> ", &mut line)?;
        if line.is_empty() {
            continue;
        }

        println!();

        return Ok(line);
    }
}

fn parse_manual_connection_string(
    connection_string: &str,
) -> Result<(String, String, Vec<u8>), String> {
    const HOSTNAME_KEY: &str = "HostName";
    const DEVICEID_KEY: &str = "DeviceId";
    const SHAREDACCESSKEY_KEY: &str = "SharedAccessKey";

    let mut iothub_hostname = None;
    let mut device_id = None;
    let mut symmetric_key = None;

    for sections in connection_string.split(';') {
        let mut parts = sections.split('=');
        match parts
            .next()
            .expect("str::split always returns at least one part")
        {
            HOSTNAME_KEY => iothub_hostname = parts.next(),
            DEVICEID_KEY => device_id = parts.next(),
            SHAREDACCESSKEY_KEY => symmetric_key = parts.next(),
            _ => (), // Ignore extraneous component in the connection string
        }
    }

    let iothub_hostname = iothub_hostname.ok_or(r#"required parameter "HostName" is missing"#)?;

    let device_id = device_id.ok_or(r#"required parameter "DeviceId" is missing"#)?;

    let symmetric_key =
        symmetric_key.ok_or(r#"required parameter "SharedAccessKey" is missing"#)?;
    let symmetric_key =
        base64::decode(symmetric_key)
        .map_err(|err| format!(r#"connection string's "SharedAccessKey" parameter could not be decoded from base64: {}"#, err))?;

    Ok((
        iothub_hostname.to_owned(),
        device_id.to_owned(),
        symmetric_key,
    ))
}

fn parse_preloaded_key_location(value: &str) -> Option<aziot_keys_common::PreloadedKeyLocation> {
    match value.parse::<aziot_keys_common::PreloadedKeyLocation>() {
        Ok(value) => Some(value),

        Err(err) => {
            // Might be a path

            let value = url::Url::from_file_path(&value)
                .map_err(|()| err) // Url::from_file_path doesn't give a printable error, so just print the original one.
                .and_then(|value| {
                    value
                        .to_string()
                        .parse::<aziot_keys_common::PreloadedKeyLocation>()
                });
            match value {
                Ok(value) => Some(value),

                Err(err) => {
                    println!(
                        "Could not parse input as a file path or a preloaded key URI: {}",
                        err
                    );
                    None
                }
            }
        }
    }
}

fn parse_cert_location(value: &str) -> Option<url::Url> {
    let value = value
        .parse::<url::Url>()
        .or_else(|err| url::Url::from_file_path(&value).map_err(|()| err));
    match value {
        Ok(value) if value.scheme() == "file" => Some(value),

        Ok(value) => {
            println!(
                r#"Input has invalid scheme {:?}. Only "file://" URIs are supported."#,
                value.scheme()
            );
            None
        }

        Err(err) => {
            println!(
                "Could not parse input as a file path or a file:// URI: {}",
                err
            );
            None
        }
    }
}

/// Prompts the user to enter an EST server URL, and fixes it to have a "/.well-known/est" component if it doesn't already.
fn read_est_url(stdin: &mut impl Reader, prompt_question: &str) -> Result<url::Url> {
    loop {
        let url = prompt(stdin, prompt_question)?;
        let url = if url.contains("/.well-known/est") {
            url
        } else {
            format!("{}/.well-known/est", url)
        };
        let url = url.trim_end_matches("/simpleenroll");
        match url.parse::<url::Url>() {
            Ok(url) if url.scheme() == "http" || url.scheme() == "https" => break Ok(url),
            Ok(_) => println!("Could not parse response as an http or https URL"),
            Err(err) => println!("Could not parse response as an http or https URL: {}", err),
        }
    }
}

fn create_dir_all(
    path: &(impl AsRef<std::path::Path> + ?Sized),
    user: &nix::unistd::User,
    mode: u32,
) -> Result<()> {
    let path = path.as_ref();
    let path_displayable = path.display();

    let () = std::fs::create_dir_all(path)
        .with_context(|| format!("could not create {} directory", path_displayable))?;
    let () = nix::unistd::chown(path, Some(user.uid), Some(user.gid))
        .with_context(|| format!("could not set ownership on {} directory", path_displayable))?;
    let () = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
        .with_context(|| {
            format!(
                "could not set permissions on {} directory",
                path_displayable
            )
        })?;
    Ok(())
}

fn write_file(
    path: &(impl AsRef<std::path::Path> + ?Sized),
    content: &[u8],
    user: &nix::unistd::User,
    mode: u32,
) -> Result<()> {
    let path = path.as_ref();
    let path_displayable = path.display();

    let () = std::fs::write(path, content)
        .with_context(|| format!("could not create {}", path_displayable))?;
    let () = nix::unistd::chown(path, Some(user.uid), Some(user.gid))
        .with_context(|| format!("could not set ownership on {}", path_displayable))?;
    let () = std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
        .with_context(|| format!("could not set permissions on {}", path_displayable))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    struct Stdin(std::io::BufReader<std::fs::File>);

    impl super::Reader for Stdin {
        fn read_line(&mut self, _prompt: &str, line: &mut String) -> std::io::Result<usize> {
            match std::io::BufRead::read_line(&mut self.0, line)? {
                0 => Err(std::io::ErrorKind::UnexpectedEof.into()),
                result => {
                    // Remove trailing newline to match `Reader::read_line` API.
                    line.pop();
                    Ok(result - 1)
                }
            }
        }

        fn read_secret(&mut self, prompt: &str, line: &mut String) -> std::io::Result<usize> {
            self.read_line(prompt, line)
        }
    }

    #[test]
    fn test() {
        let files_directory =
            std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/test-files/init"));
        for entry in std::fs::read_dir(files_directory).unwrap() {
            let entry = entry.unwrap();
            if !entry.file_type().unwrap().is_dir() {
                continue;
            }

            let case_directory = entry.path();

            let test_name = case_directory.file_name().unwrap().to_str().unwrap();

            println!(".\n.\n=========\n.\nRunning test {}", test_name);

            let mut input = Stdin(std::io::BufReader::new(
                std::fs::File::open(case_directory.join("input.txt")).unwrap(),
            ));
            let expected_keyd_config = std::fs::read(case_directory.join("keyd.toml")).unwrap();
            let expected_certd_config = std::fs::read(case_directory.join("certd.toml")).unwrap();
            let expected_identityd_config =
                std::fs::read(case_directory.join("identityd.toml")).unwrap();
            let expected_tpmd_config = std::fs::read(case_directory.join("tpmd.toml")).unwrap();

            let expected_preloaded_device_id_pk_bytes =
                match std::fs::read(case_directory.join("device-id")) {
                    Ok(contents) => Some(contents),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                    Err(err) => panic!("could not read device-id file: {}", err),
                };

            let super::RunOutput {
                keyd_config: actual_keyd_config,
                certd_config: actual_certd_config,
                identityd_config: actual_identityd_config,
                tpmd_config: actual_tpmd_config,
                preloaded_device_id_pk_bytes: actual_preloaded_device_id_pk_bytes,
            } = super::run_inner(&mut input).unwrap();

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
