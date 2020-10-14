// Copyright (c) Microsoft. All rights reserved.

// This subcommand interactively asks the user to give out basic provisioning information for their device and
// creates the config files for the three services based on that information.
//
// Notes:
//
// - Provisioning with a symmetric key (manual or DPS) requires the key to be preloaded into KS, which means it needs to be
//   saved to a file. This subcommand uses a file named `/var/secrets/aziot/keyd/device-id` for that purpose.
//   It creates the directory structure and ACLs the directory and the file appropriately to the KS user.
//
// - `dynamic_reprovisioning` is enabled by default in IS provisioning settings.

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

pub(crate) fn run() -> Result<(), crate::Error> {
	// Get the three users.
	//
	// In debug builds, we allow `aziot init` to be run without root. In that case, use the current user.

	let aziotks_user =
		(
			if cfg!(debug_assertions) && !nix::unistd::Uid::current().is_root() {
				nix::unistd::User::from_uid(nix::unistd::Uid::current())
			}
			else {
				nix::unistd::User::from_name("aziotks")
			}
		)
		.map_err(|err| format!("could not query aziotks user information: {}", err))?
		.ok_or_else(|| "could not query aziotks user information")?;

	let aziotcs_user =
		(
			if cfg!(debug_assertions) && !nix::unistd::Uid::current().is_root() {
				nix::unistd::User::from_uid(nix::unistd::Uid::current())
			}
			else {
				nix::unistd::User::from_name("aziotcs")
			}
		)
		.map_err(|err| format!("could not query aziotcs user information: {}", err))?
		.ok_or_else(|| "could not query aziotcs user information")?;

	let aziotid_user =
		(
			if cfg!(debug_assertions) && !nix::unistd::Uid::current().is_root() {
				nix::unistd::User::from_uid(nix::unistd::Uid::current())
			}
			else {
				nix::unistd::User::from_name("aziotid")
			}
		)
		.map_err(|err| format!("could not query aziotid user information: {}", err))?
		.ok_or_else(|| "could not query aziotid user information")?;

	for &f in &["/etc/aziot/certd/config.toml", "/etc/aziot/identityd/config.toml", "/etc/aziot/keyd/config.toml"] {
		// Don't overwrite any of the configs if they already exist.
		//
		// It would be less racy to test this right before we're about to overwrite the files, but by then we'll have asked the user
		// all of the questions and it would be a waste to give up.
		if std::path::Path::new(f).exists() {
			return Err(format!("\
				Cannot run because file {} already exists. \
				Delete this file (after taking a backup if necessary) before running this command.\
			", f).into());
		}
	}

	let stdin = std::io::stdin();
	let mut stdin = stdin.lock();

	let (
		keyd_config,
		certd_config,
		identityd_config,
		device_id_pk_bytes,
	) = run_inner(&mut stdin)?;

	if let Some(device_id_pk_bytes) = device_id_pk_bytes {
		println!("Note: Symmetric key will be written to /var/secrets/aziot/keyd/device-id");

		create_dir_all("/var/secrets/aziot/keyd", &aziotks_user, 0o0700)?;
		write_file("/var/secrets/aziot/keyd/device-id", &device_id_pk_bytes, &aziotks_user, 0o0600)?;
	}

	write_file("/etc/aziot/keyd/config.toml", &keyd_config, &aziotks_user, 0o0600)?;

	write_file("/etc/aziot/certd/config.toml", &certd_config, &aziotcs_user, 0o0600)?;

	write_file("/etc/aziot/identityd/config.toml", &identityd_config, &aziotid_user, 0o0600)?;

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

/// Returns the KS/CS/IS configs, and optionally the contents of a new /var/secrets/aziot/keyd/device-id file to hold the device ID symmetric key.
fn run_inner(stdin: &mut impl std::io::BufRead) -> Result<(
	Vec<u8>,
	Vec<u8>,
	Vec<u8>,
	Option<Vec<u8>>,
), crate::Error> {
	println!("Welcome to the configuration tool for aziot-identity-service.");
	println!();
	println!("This command will set up the configurations for aziot-keyd, aziot-certd and aziot-identityd.");
	println!();

	// In production, running as root is the easiest way to guarantee the tool has write access to every service's config file.
	// But allow running as a regular use in debug builds for the sake of development.
	if !cfg!(debug_assertions) && !nix::unistd::Uid::current().is_root() {
		return Err("this command must be run as root".into());
	}

	let (
		provisioning_type,
		preloaded_device_id_pk_bytes,
	) = choose! {
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
				aziot_identityd::settings::ProvisioningType::Manual {
					iothub_hostname,
					device_id,
					authentication: aziot_identityd::settings::ManualAuthMethod::SharedPrivateKey {
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
				let symmetric_key = prompt(stdin, "Enter the device symmetric key (in its original base64 form).")?;
				match base64::decode(symmetric_key) {
					Ok(symmetric_key) => break symmetric_key,
					Err(err) => println!(r#"Symmetric key could not be decoded from base64: {}"#, err),
				}
			};

			(
				aziot_identityd::settings::ProvisioningType::Manual {
					iothub_hostname,
					device_id,
					authentication: aziot_identityd::settings::ManualAuthMethod::SharedPrivateKey {
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
				aziot_identityd::settings::ProvisioningType::Manual {
					iothub_hostname,
					device_id,
					authentication: aziot_identityd::settings::ManualAuthMethod::X509 {
						identity_cert: DEVICE_ID_ID.to_owned(),
						identity_pk: DEVICE_ID_ID.to_owned(),
					},
				},
				None,
			)
		},

		ProvisioningMethod::DpsSymmetricKey => {
			let scope_id = prompt(stdin, "Enter the DPS scope ID.")?;
			let registration_id = prompt(stdin, "Enter the DPS registration ID.")?;
			let symmetric_key = loop {
				let symmetric_key = prompt(stdin, "Enter the DPS symmetric key (in its original base64 form)..")?;
				match base64::decode(symmetric_key) {
					Ok(symmetric_key) => break symmetric_key,
					Err(err) => println!(r#"Symmetric key could not be decoded from base64: {}"#, err),
				}
			};

			(
				aziot_identityd::settings::ProvisioningType::Dps {
					global_endpoint: DPS_GLOBAL_ENDPOINT.to_owned(),
					scope_id,
					attestation: aziot_identityd::settings::DpsAttestationMethod::SymmetricKey {
						registration_id,
						symmetric_key: DEVICE_ID_ID.to_owned(),
					},
				},
				Some(symmetric_key),
			)
		},

		ProvisioningMethod::DpsX509 => {
			let scope_id = prompt(stdin, "Enter the DPS scope ID.")?;
			let registration_id = prompt(stdin, "Enter the DPS registration ID.")?;

			(
				aziot_identityd::settings::ProvisioningType::Dps {
					global_endpoint: DPS_GLOBAL_ENDPOINT.to_owned(),
					scope_id,
					attestation: aziot_identityd::settings::DpsAttestationMethod::X509 {
						registration_id,
						identity_cert: DEVICE_ID_ID.to_owned(),
						identity_pk: DEVICE_ID_ID.to_owned(),
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
		let mut keyd_config = aziot_keyd::Config {
			aziot_keys: Default::default(),
			preloaded_keys: Default::default(),
			endpoints: Default::default(),
		};

		keyd_config.aziot_keys.insert("homedir_path".to_owned(), AZIOT_KEYD_HOMEDIR_PATH.to_owned());

		if uses_pkcs11 {
			let pkcs11_lib_path = prompt(stdin, "Enter the path of the PKCS#11 library.")?;
			let pkcs11_base_slot = prompt(stdin, "Enter the PKCS#11 URI of a slot in the HSM that will be used for storing new keys at runtime.")?;
			keyd_config.aziot_keys.insert("pkcs11_lib_path".to_owned(), pkcs11_lib_path);
			keyd_config.aziot_keys.insert("pkcs11_base_slot".to_owned(), pkcs11_base_slot);
		}

		if preloaded_device_id_pk_bytes.is_some() {
			keyd_config.preloaded_keys.insert(DEVICE_ID_ID.to_owned(), "file:///var/secrets/aziot/keyd/device-id".to_owned());
		}
		else if matches!(
			provisioning_type,
			aziot_identityd::settings::ProvisioningType::Manual { authentication: aziot_identityd::settings::ManualAuthMethod::X509 { .. }, .. } |
			aziot_identityd::settings::ProvisioningType::Dps { attestation: aziot_identityd::settings::DpsAttestationMethod::X509 { .. }, .. }
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
						if let Some(device_id_pk_uri) = convert_path_or_uri_to_uri(device_id_pk_uri) {
							break device_id_pk_uri;
						}
					};
					keyd_config.preloaded_keys.insert(DEVICE_ID_ID.to_owned(), device_id_pk_uri);

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
					let local_ca_uri = loop {
						let local_ca_uri = prompt(stdin, prompt_question)?;
						if let Some(local_ca_uri) = convert_path_or_uri_to_uri(local_ca_uri) {
							break local_ca_uri;
						}
					};
					keyd_config.preloaded_keys.insert(LOCAL_CA.to_owned(), local_ca_uri);

					DeviceIdSource::LocalCa
				},

				DeviceIdSource::Est => DeviceIdSource::Est,
			});
		}

		keyd_config
	};

	let certd_config = {
		let mut certd_config = aziot_certd::Config {
			homedir_path: AZIOT_CERTD_HOMEDIR_PATH.into(),
			cert_issuance: Default::default(),
			preloaded_certs: Default::default(),
			endpoints: Default::default(),
		};

		match device_id_source {
			Some(DeviceIdSource::Preloaded) => {
				let device_id_cert_uri = loop {
					let device_id_cert_uri = prompt(stdin, "Enter the filesystem path of the device ID certificate file.")?;
					if let Some(device_id_cert_uri) = convert_path_or_uri_to_uri(device_id_cert_uri) {
						match device_id_cert_uri.parse() {
							Ok(device_id_cert_uri) => break device_id_cert_uri,
							Err(err) => println!("Could not convert to a file:// URI: {}", err),
						}
					}
				};
				let device_id_cert_uri = aziot_certd::PreloadedCert::Uri(device_id_cert_uri);
				certd_config.preloaded_certs.insert(DEVICE_ID_ID.to_owned(), device_id_cert_uri);
			},

			Some(DeviceIdSource::LocalCa) => {
				let local_ca_cert_uri = loop {
					let local_ca_cert_uri = prompt(stdin, "Enter the filesystem path of the CA certificate file.")?;
					if let Some(local_ca_cert_uri) = convert_path_or_uri_to_uri(local_ca_cert_uri) {
						match local_ca_cert_uri.parse() {
							Ok(local_ca_cert_uri) => break local_ca_cert_uri,
							Err(err) => println!("Could not convert to a file:// URI: {}", err),
						}
					}
				};
				let local_ca_cert_uri = aziot_certd::PreloadedCert::Uri(local_ca_cert_uri);
				certd_config.preloaded_certs.insert(LOCAL_CA.to_owned(), local_ca_cert_uri);

				certd_config.cert_issuance.local_ca = Some(aziot_certd::LocalCa {
					cert: LOCAL_CA.to_owned(),
					pk: LOCAL_CA.to_owned(),
				});

				certd_config.cert_issuance.certs.insert(DEVICE_ID_ID.to_owned(), aziot_certd::CertIssuanceOptions {
					method: aziot_certd::CertIssuanceMethod::LocalCa,
					common_name: None,
					expiry_days: None,
				});
			},

			Some(DeviceIdSource::Est) => {
				certd_config.cert_issuance.certs.insert(DEVICE_ID_ID.to_owned(), aziot_certd::CertIssuanceOptions {
					method: aziot_certd::CertIssuanceMethod::Est,
					common_name: None,
					expiry_days: None,
				});

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
							if let Some(est_trusted_cert_uri) = convert_path_or_uri_to_uri(est_trusted_cert_uri) {
								match est_trusted_cert_uri.parse() {
									Ok(est_trusted_cert_uri) => break est_trusted_cert_uri,
									Err(err) => println!("Could not convert to a file:// URI: {}", err),
								}
							}
						};
						let est_trusted_cert_uri = aziot_certd::PreloadedCert::Uri(est_trusted_cert_uri);
						certd_config.preloaded_certs.insert(EST_SERVER_CA_ID.to_owned(), est_trusted_cert_uri);

						vec![EST_SERVER_CA_ID.to_owned()]
					},
				};

				let est_auth_basic = choose! {
					stdin,
					"Does your EST server use a username and password for authentication?",

					YesNo::Yes => {
						let username = prompt(stdin, "Enter the username used to authenticate with your EST server.")?;
						// It would be nice to use the rpassword crate so that the password isn't echoed as the user types it.
						// But the rpassword crates needs access to the real stdin to be able to disable the echo attribute on it,
						// which we cannot give it because we've locked stdin ourselves.

						let password = prompt(stdin, "Enter the password used to authenticate with your EST server.")?;
						Some(aziot_certd::EstAuthBasic {
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
								if let Some(est_id_pk_uri) = convert_path_or_uri_to_uri(est_id_pk_uri) {
									break est_id_pk_uri;
								}
							};
							keyd_config.preloaded_keys.insert(EST_ID_ID.to_owned(), est_id_pk_uri);

							let est_id_cert_uri = loop {
								let est_id_cert_uri = prompt(stdin, "Enter the filesystem path of the EST ID certificate file.")?;
								if let Some(est_id_cert_uri) = convert_path_or_uri_to_uri(est_id_cert_uri) {
									match est_id_cert_uri.parse() {
										Ok(est_id_cert_uri) => break est_id_cert_uri,
										Err(err) => println!("Could not convert to a file:// URI: {}", err),
									}
								}
							};
							let est_id_cert_uri = aziot_certd::PreloadedCert::Uri(est_id_cert_uri);
							certd_config.preloaded_certs.insert(EST_ID_ID.to_owned(), est_id_cert_uri);

							Some(aziot_certd::EstAuthX509 {
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
								if let Some(est_bootstrap_id_pk_uri) = convert_path_or_uri_to_uri(est_bootstrap_id_pk_uri) {
									break est_bootstrap_id_pk_uri;
								}
							};
							keyd_config.preloaded_keys.insert(EST_BOOTSTRAP_ID.to_owned(), est_bootstrap_id_pk_uri);

							let est_bootstrap_id_cert_uri = loop {
								let est_bootstrap_id_cert_uri = prompt(stdin, "Enter the filesystem path of the EST bootstrap ID certificate file.")?;
								if let Some(est_bootstrap_id_cert_uri) = convert_path_or_uri_to_uri(est_bootstrap_id_cert_uri) {
									match est_bootstrap_id_cert_uri.parse() {
										Ok(est_bootstrap_id_cert_uri) => break est_bootstrap_id_cert_uri,
										Err(err) => println!("Could not convert to a file:// URI: {}", err),
									}
								}
							};
							let est_bootstrap_id_cert_uri = aziot_certd::PreloadedCert::Uri(est_bootstrap_id_cert_uri);
							certd_config.preloaded_certs.insert(EST_BOOTSTRAP_ID.to_owned(), est_bootstrap_id_cert_uri);

							Some(aziot_certd::EstAuthX509 {
								identity: (EST_ID_ID.to_owned(), EST_ID_ID.to_owned()),
								bootstrap_identity: Some((EST_BOOTSTRAP_ID.to_owned(), EST_BOOTSTRAP_ID.to_owned())),
							})
						},
					},

					YesNo::No => None,
				};

				certd_config.cert_issuance.est = Some(aziot_certd::Est {
					auth: aziot_certd::EstAuth {
						basic: est_auth_basic,
						x509: est_auth_x509,
					},

					trusted_certs,

					urls,
				});
			},

			None => (),
		}

		certd_config
	};

	let keyd_config = toml::to_vec(&keyd_config).map_err(|err| format!("could not serialize aziot-keyd config: {}", err))?;
	let certd_config = toml::to_vec(&certd_config).map_err(|err| format!("could not serialize aziot-certd config: {}", err))?;

	let identityd_config = {
		aziot_identityd::settings::Settings {
			hostname: get_hostname()?,
			homedir: AZIOT_IDENTITYD_HOMEDIR_PATH.into(),
			principal: vec![],
			provisioning: aziot_identityd::settings::Provisioning {
				dynamic_reprovisioning: true,
				provisioning: provisioning_type,
			},
			endpoints: Default::default(),
			localid: None,
		}
	};
	let identityd_config = toml::to_vec(&identityd_config).map_err(|err| format!("could not serialize aziot-identityd config: {}", err))?;

	Ok((
		keyd_config,
		certd_config,
		identityd_config,
		preloaded_device_id_pk_bytes,
	))
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

	#[display(fmt = "Manual provisioning with device identity certificate (self-signed or CA-signed)")]
	ManualX509,

	#[display(fmt = "DPS provisioning with symmetric key")]
	DpsSymmetricKey,

	#[display(fmt = "DPS provisioning with device identity certificate (self-signed or CA-signed)")]
	DpsX509,
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

	#[display(fmt = "Issued dynamically from the EST server using a different client certificate (a \"bootstrap EST ID\" certificate)")]
	Bootstrap,
}

#[derive(Clone, Copy, Debug, derive_more::Display)]
enum EstTrustedCert {
	#[display(fmt = "My EST server's server certificate can be validated with just the CA certificates already installed on my OS")]
	Os,

	#[display(fmt = "My EST server's server certificate can only be validated with a separate CA certificate.")]
	Separate,
}

fn choose<'a, TChoice>(
	stdin: &mut impl std::io::BufRead,
	question: &str,
	choices: &'a [TChoice],
) -> Result<&'a TChoice, crate::Error> where TChoice: std::fmt::Display {
	println!("{}", question);

	#[allow(
		clippy::cast_possible_truncation,
		clippy::cast_precision_loss,
		clippy::cast_sign_loss,
	)]
	let max_choice_width = (choices.len() as f64).log10() as usize + 1;

	println!();
	for (i, choice) in choices.iter().enumerate() {
		println!("{:>max_choice_width$}: {}", i + 1, choice, max_choice_width = max_choice_width);
	}
	println!();

	let prompt_question = format!("Enter a choice [1-{}]", choices.len());

	loop {
		let answer = prompt(stdin, &prompt_question)?;
		let answer =
			answer.parse().ok()
			.and_then(|choice: usize| choice.checked_sub(1))
			.and_then(|choice| choices.get(choice));
		if let Some(answer) = answer {
			return Ok(answer);
		}

		print!("Invalid choice. ");
	}
}

fn prompt(stdin: &mut impl std::io::BufRead, question: &str) -> Result<String, crate::Error> {
	println!("{}", question);

	let mut line = String::new();

	loop {
		print!("> ");
		std::io::Write::flush(&mut std::io::stdout())?;

		stdin.read_line(&mut line)?;
		if line.is_empty() {
			return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof).into());
		}

		println!();

		let answer = line.trim();
		if !answer.is_empty() {
			return Ok(answer.to_owned());
		}
	}
}

fn parse_manual_connection_string(connection_string: &str) -> Result<(String, String, Vec<u8>), String> {
	const HOSTNAME_KEY: &str = "HostName";
	const DEVICEID_KEY: &str = "DeviceId";
	const SHAREDACCESSKEY_KEY: &str = "SharedAccessKey";

	let mut iothub_hostname = None;
	let mut device_id = None;
	let mut symmetric_key = None;

	for sections in connection_string.split(';') {
		let mut parts = sections.split('=');
		match parts.next().expect("str::split always returns at least one part") {
			HOSTNAME_KEY => iothub_hostname = parts.next(),
			DEVICEID_KEY => device_id = parts.next(),
			SHAREDACCESSKEY_KEY => symmetric_key = parts.next(),
			_ => (), // Ignore extraneous component in the connection string
		}
	}

	let iothub_hostname = iothub_hostname.ok_or(r#"required parameter "HostName" is missing"#)?;

	let device_id = device_id.ok_or(r#"required parameter "DeviceId" is missing"#)?;

	let symmetric_key = symmetric_key.ok_or(r#"required parameter "SharedAccessKey" is missing"#)?;
	let symmetric_key =
		base64::decode(symmetric_key)
		.map_err(|err| format!(r#"connection string's "SharedAccessKey" parameter could not be decoded from base64: {}"#, err))?;

	Ok((iothub_hostname.to_owned(), device_id.to_owned(), symmetric_key))
}

fn convert_path_or_uri_to_uri(value: String) -> Option<String> {
	if value.starts_with("file://") || value.starts_with("pkcs11:") {
		Some(value)
	}
	else {
		match url::Url::from_file_path(&value) {
			Ok(value) => Some(value.to_string()),
			Err(()) => {
				println!("Could not convert path to a file:// URI");
				None
			},
		}
	}
}

fn get_hostname() -> Result<String, crate::Error> {
	if cfg!(test) {
		Ok("my-device".to_owned())
	}
	else {
		let mut hostname = vec![0_u8; 256];
		let hostname = nix::unistd::gethostname(&mut hostname).map_err(|err| format!("could not get machine hostname: {}", err))?;
		let hostname = hostname.to_str().map_err(|err| format!("could not get machine hostname: {}", err))?;
		Ok(hostname.to_owned())
	}
}

/// Prompts the user to enter an EST server URL, and fixes it to have a "/.well-known/est" component if it doesn't already.
fn read_est_url(stdin: &mut impl std::io::BufRead, prompt_question: &str) -> Result<url::Url, crate::Error> {
	loop {
		let url = prompt(stdin, prompt_question)?;
		let url =
			if url.contains("/.well-known/est") {
				url
			}
			else {
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
) -> Result<(), crate::Error> {
	let path = path.as_ref();
	let path_displayable = path.display();

	let () =
		std::fs::create_dir_all(path)
		.map_err(|err| format!("could not create {} directory: {}", path_displayable, err))?;
	let () =
		nix::unistd::chown(path, Some(user.uid), Some(user.gid))
		.map_err(|err| format!("could not set ownership on {} directory: {}", path_displayable, err))?;
	let () =
		std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
		.map_err(|err| format!("could not set permissions on {} directory: {}", path_displayable, err))?;
	Ok(())
}

fn write_file(
	path: &(impl AsRef<std::path::Path> + ?Sized),
	content: &[u8],
	user: &nix::unistd::User,
	mode: u32,
) -> Result<(), crate::Error> {
	let path = path.as_ref();
	let path_displayable = path.display();

	let () =
		std::fs::write(path, content)
		.map_err(|err| format!("could not create {}: {}", path_displayable, err))?;
	let () =
		nix::unistd::chown(path, Some(user.uid), Some(user.gid))
		.map_err(|err| format!("could not set ownership on {}: {}", path_displayable, err))?;
	let () =
		std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
		.map_err(|err| format!("could not set permissions on {}: {}", path_displayable, err))?;
	Ok(())
}

#[cfg(test)]
mod tests {
	#[test]
	fn test() {
		let files_directory = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/test-files/init"));
		for entry in std::fs::read_dir(files_directory).unwrap() {
			let entry = entry.unwrap();
			if !entry.file_type().unwrap().is_dir() {
				continue;
			}

			let case_directory = entry.path();

			let test_name = case_directory.file_name().unwrap().to_str().unwrap();

			println!("Running test {}", test_name);

			let mut input = std::io::BufReader::new(std::fs::File::open(case_directory.join("input.txt")).unwrap());
			let expected_keyd_config = std::fs::read(case_directory.join("keyd.toml")).unwrap();
			let expected_certd_config = std::fs::read(case_directory.join("certd.toml")).unwrap();
			let expected_identityd_config = std::fs::read(case_directory.join("identityd.toml")).unwrap();

			let expected_device_id_pk_bytes = match std::fs::read(case_directory.join("device-id")) {
				Ok(contents) => Some(contents),
				Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
				Err(err) => panic!("could not read device-id file: {}", err),
			};

			let (
				actual_keyd_config,
				actual_certd_config,
				actual_identityd_config,
				actual_device_id_pk_bytes,
			) = super::run_inner(&mut input).unwrap();

			// Convert the three configs to bytes::Bytes before asserting, because bytes::Bytes's Debug format prints strings.
			// It doesn't matter for the device ID file since it's binary anyway.
			assert_eq!(bytes::Bytes::from(expected_keyd_config), bytes::Bytes::from(actual_keyd_config), "keyd config does not match");
			assert_eq!(bytes::Bytes::from(expected_certd_config), bytes::Bytes::from(actual_certd_config), "certd config does not match");
			assert_eq!(bytes::Bytes::from(expected_identityd_config), bytes::Bytes::from(actual_identityd_config), "identityd config does not match");
			assert_eq!(expected_device_id_pk_bytes, actual_device_id_pk_bytes, "device ID key bytes do not match");
		}
	}
}
