// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::default_trait_access,
	clippy::let_and_return,
	clippy::let_unit_value,
	clippy::missing_errors_doc,
	clippy::similar_names,
	clippy::too_many_lines,
)]

mod config;
pub use config::{Config, Endpoints};

mod error;
pub use error::{Error, InternalError};

mod est;

pub struct Server {
	homedir_path: std::path::PathBuf,
	cert_issuance: crate::config::CertIssuance,
	preloaded_certs: std::collections::BTreeMap<String, crate::config::PreloadedCert>,

	key_client: std::sync::Arc<aziot_key_client::Client>,
	key_engine: openssl2::FunctionalEngine,
}

impl Server {
	pub fn new(
		homedir_path: std::path::PathBuf,
		cert_issuance: crate::config::CertIssuance,
		preloaded_certs: std::collections::BTreeMap<String, crate::config::PreloadedCert>,
		key_client: std::sync::Arc<aziot_key_client::Client>,
	) -> Result<Self, Error> {
		let key_engine = aziot_key_openssl_engine::load(key_client.clone()).map_err(|err| Error::Internal(InternalError::LoadKeyOpensslEngine(err)))?;

		Ok(Server {
			homedir_path,
			cert_issuance,
			preloaded_certs,

			key_client,
			key_engine,
		})
	}
}

impl Server {
	pub async fn create_cert(
		this: std::sync::Arc<futures_util::lock::Mutex<Server>>,
		id: String,
		csr: Vec<u8>,
		issuer: Option<(String, aziot_key_common::KeyHandle)>,
	) -> Result<Vec<u8>, Error> {
		let mut this = this.lock().await;

		let x509 =
			create_cert(
				&mut *this,
				&id,
				&csr,
				issuer.as_ref().map(|(issuer_cert, issuer_private_key)| (&**issuer_cert, issuer_private_key)),
			).await?;

		Ok(x509)
	}

	pub fn import_cert(
		&mut self,
		id: &str,
		pem: &[u8],
	) -> Result<(), Error> {
		let path = get_path(&self.homedir_path, &self.preloaded_certs, id)?;
		std::fs::write(path, pem).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
		Ok(())
	}

	pub fn get_cert(
		&mut self,
		id: &str,
	) -> Result<Vec<u8>, Error> {
		let bytes =
			get_cert_inner(&self.homedir_path, &self.preloaded_certs, id)?
			.ok_or_else(|| Error::invalid_parameter("id", "not found"))?;
		Ok(bytes)
	}

	pub fn delete_cert(
		&mut self,
		id: &str,
	) -> Result<(), Error> {
		let path = get_path(&self.homedir_path, &self.preloaded_certs, id)?;
		match std::fs::remove_file(path) {
			Ok(()) => Ok(()),
			Err(ref err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
			Err(err) => Err(Error::Internal(InternalError::DeleteFile(err))),
		}
	}
}

fn get_path(
	homedir_path: &std::path::Path,
	preloaded_certs: &std::collections::BTreeMap<String, config::PreloadedCert>,
	cert_id: &str,
) -> Result<std::path::PathBuf, Error> {
	if let Some(preloaded_cert) = preloaded_certs.get(cert_id) {
		let path = get_preloaded_cert_path(preloaded_cert, cert_id)?;
		return Ok(path);
	}

	let mut path = homedir_path.to_owned();
	path.push("certs");

	if !path.exists() {
		let () = std::fs::create_dir_all(&path).map_err(|err| Error::Internal(InternalError::GetPath(Box::new(err))))?;
	}

	let id_sanitized: String = cert_id.chars().filter(char::is_ascii_alphanumeric).collect();

	let hash =
		openssl::hash::hash(openssl::hash::MessageDigest::sha256(), cert_id.as_bytes())
		.map_err(|err| Error::Internal(InternalError::GetPath(Box::new(err))))?;
	let hash = hex::encode(hash);
	path.push(format!("{}-{}.cer", id_sanitized, hash));

	Ok(path)
}

fn get_preloaded_cert_path(preloaded_cert: &config::PreloadedCert, cert_id: &str) -> Result<std::path::PathBuf, Error> {
	match preloaded_cert {
		config::PreloadedCert::Uri(uri) => {
			let scheme = uri.scheme();
			if scheme != "file" {
				return Err(Error::Internal(InternalError::GetPath(format!(
					"preloaded cert {:?} does not have a valid URI: unrecognized scheme {:?}",
					cert_id, scheme,
				).into())));
			}

			let path =
				uri.to_file_path()
				.map_err(|()| Error::Internal(InternalError::GetPath(format!(
					"preloaded cert {:?} does not have a valid URI: not a valid path",
					cert_id,
				).into())))?;

			Ok(path)
		},

		config::PreloadedCert::Ids(_) => Err(Error::Internal(InternalError::GetPath(format!(
			"preloaded cert {:?} is a list of IDs, not a single URI",
			cert_id,
		).into()))),
	}
}

fn load_inner(path: &std::path::Path) -> Result<Option<Vec<u8>>, Error> {
	match std::fs::read(path) {
		Ok(cert_bytes) => Ok(Some(cert_bytes)),
		Err(ref err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
		Err(err) => Err(Error::Internal(InternalError::ReadFile(err))),
	}
}

fn create_cert<'a>(
	server: &'a mut Server,
	id: &'a str,
	csr: &'a [u8],
	issuer: Option<(&'a str, &'a aziot_key_common::KeyHandle)>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, Error>> + Send + 'a>> {
	// Creating a cert is recursive in some cases. An async fn cannot recurse because its RPIT Future type would end up being infinitely sized,
	// so it needs to be boxed. So we have a non-async fn returning a boxed future, where the future being boxed is the result of an inner asyn fn,
	// and the recursive call is for the outer boxed-future-returning fn.

	async fn create_cert_inner(
		server: &mut Server,
		id: &str,
		csr: &[u8],
		issuer: Option<(&str, &aziot_key_common::KeyHandle)>,
	) -> Result<Vec<u8>, Error> {
		// Look up issuance options for this certificate ID.
		let cert_options = server.cert_issuance.certs.get(id);

		if let Some((issuer_id, issuer_private_key)) = issuer {
			// Issuer is explicitly specified, so load it and use it to sign the CSR.

			let x509_req = openssl::x509::X509Req::from_pem(csr).map_err(|err| Error::invalid_parameter("csr", err))?;
			let x509_req_public_key = x509_req.public_key().map_err(|err| Error::invalid_parameter("csr", err))?;
			if !x509_req.verify(&x509_req_public_key).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))? {
				return Err(Error::invalid_parameter("csr", "CSR failed to be verified with its public key"));
			}

			// If issuance options are not provided for this certificate ID, use defaults.
			let mut expiry_days = 30;
			let mut subject_name = x509_req.subject_name();
			let common_name;

			if let Some(options) = cert_options {
				if let Some(d) = options.expiry_days {
					expiry_days = d;
				}

				if let Some(c) = &options.common_name {
					let mut name_builder = openssl::x509::X509Name::builder()
						.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

					name_builder.append_entry_by_text("CN", &c).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
					common_name = name_builder.build();
					subject_name = &common_name;
				}
			}

			let mut x509 = openssl::x509::X509::builder().map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
			x509.set_subject_name(subject_name).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
			x509.set_pubkey(&x509_req_public_key).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

			x509.set_not_before(
				&*openssl::asn1::Asn1Time::days_from_now(0)
				.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?
			).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
			x509.set_not_after(
				&*openssl::asn1::Asn1Time::days_from_now(expiry_days)
				.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?
			).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

			// Copy extensions from x509_req to the new cert.
			let req_extensions = x509_req.extensions();

			// x509_req.extensions() returns an Err variant if no extensions are present in the req.
			// Ignore this Err and only copy extensions if provided in the req.
			if let Ok(req_extensions) = req_extensions {
				for extension in req_extensions {
					x509.append_extension(extension).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
				}
			}

			let issuer_private_key =
				std::ffi::CString::new(issuer_private_key.0.clone()).map_err(|err| Error::invalid_parameter("issuer.privateKeyHandle", err))?;
			let issuer_private_key =
				server.key_engine.load_private_key(&issuer_private_key).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

			let x509 =
				if issuer_id == id {
					// Issuer is the same as the cert being created, which means the caller wants the cert to be self-signed.

					x509.sign(&issuer_private_key, openssl::hash::MessageDigest::sha256()).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

					let x509 = x509.build();

					let x509 = x509.to_pem().map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
					x509
				}
				else {
					// Load the issuer and use it to sign the CSR.

					let issuer_path = get_path(&server.homedir_path, &server.preloaded_certs, issuer_id)?;
					let issuer_x509_pem =
						load_inner(&issuer_path)
						.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?
						.ok_or_else(|| Error::invalid_parameter("issuer.certId", "not found"))?;
					let issuer_x509 = openssl::x509::X509::stack_from_pem(&issuer_x509_pem).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
					let issuer_x509 = issuer_x509.get(0).ok_or_else(|| Error::invalid_parameter("issuer.certId", "invalid issuer"))?;

					x509.set_issuer_name(issuer_x509.subject_name()).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

					x509.sign(&issuer_private_key, openssl::hash::MessageDigest::sha256()).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

					let x509 = x509.build();

					let mut x509 = x509.to_pem().map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

					x509.push(b'\n');
					x509.extend_from_slice(&issuer_x509_pem);
					x509
				};

			let path = get_path(&server.homedir_path, &server.preloaded_certs, id)?;
			std::fs::write(path, &x509).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

			Ok(x509)
		}
		else {
			// Issuer is not explicitly specified, so use the issuance options for this cert from the configuration.

			let cert_options: &config::CertIssuanceOptions = cert_options.ok_or_else(||
				Error::invalid_parameter("issuer", "issuer is required for locally-issued certs")
			)?;

			match cert_options.method  {
				config::CertIssuanceMethod::Est => {
					let config::Est { auth, trusted_certs, urls } =
						server.cert_issuance.est.as_ref()
						.ok_or_else(|| Error::Internal(InternalError::CreateCert(format!(
							"cert {:?} is configured to be issued by EST, but EST is not configured",
							id,
						).into())))?;

					let url =
						urls.get(id)
						.or_else(|| urls.get("default"))
						.ok_or_else(|| Error::Internal(InternalError::CreateCert(format!(
							"cert {:?} is configured to be issued by EST, but the EST endpoint URL for it is not configured",
							id,
						).into())))?;

					let auth_basic = auth.basic.as_ref().map(|config::EstAuthBasic { username, password }| (&**username, &**password));

					let mut trusted_certs_x509 = vec![];
					for trusted_cert in trusted_certs {
						let pem =
							get_cert_inner(&server.homedir_path, &server.preloaded_certs, trusted_cert)?
							.ok_or_else(|| Error::Internal(InternalError::CreateCert(format!(
								"cert_issuance.est.trusted_certs contains unreadable cert {:?}",
								trusted_cert,
							).into())))?;
						let x509 =
							openssl::x509::X509::stack_from_pem(&pem)
							.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
						trusted_certs_x509.extend(x509);
					}

					if let Some(config::EstAuthX509 { identity: (identity_cert, identity_private_key), bootstrap_identity }) = &auth.x509 {
						// We need to use TLS client cert auth with the EST server.
						//
						// Try to load the EST identity cert.

						let identity = match get_cert_inner(&server.homedir_path, &server.preloaded_certs, identity_cert) {
							Ok(Some(identity_cert)) => match server.key_client.load_key_pair(identity_private_key) {
								Ok(identity_private_key) => Ok((identity_cert, identity_private_key)),
								Err(err) => Err(format!("could not get EST identity cert private key: {}", err)),
							},
							Ok(None) => Err(format!("could not get EST identity cert: {}", std::io::Error::from(std::io::ErrorKind::NotFound))),
							Err(err) => Err(format!("could not get EST identity cert: {}", err)),
						};

						match identity {
							Ok((identity_cert, identity_private_key)) => {
								let identity_private_key =
									std::ffi::CString::new(identity_private_key.0.clone())
									.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
								let identity_private_key =
									server.key_engine.load_private_key(&identity_private_key)
									.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

								let x509 = est::create_cert(
									csr.to_owned(),
									url,
									auth_basic,
									Some((&identity_cert, &identity_private_key)),
									trusted_certs_x509,
								).await?;

								let path = get_path(&server.homedir_path, &server.preloaded_certs, id)?;
								std::fs::write(path, &x509).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

								Ok(x509)
							},

							Err(identity_err) => {
								// EST identity cert could not be loaded. We need to issue a new one using the EST bootstrap identity cert.
								let bootstrap_identity =
									if let Some((bootstrap_identity_cert, bootstrap_identity_private_key)) = bootstrap_identity {
										match get_cert_inner(&server.homedir_path, &server.preloaded_certs, bootstrap_identity_cert) {
											Ok(Some(bootstrap_identity_cert)) => match server.key_client.load_key_pair(bootstrap_identity_private_key) {
												Ok(bootstrap_identity_private_key) => Ok((bootstrap_identity_cert, bootstrap_identity_private_key)),
												Err(err) => Err(format!("could not get EST bootstrap identity cert private key: {}", err)),
											},

											Ok(None) => Err(format!(
												"could not get EST bootstrap identity cert: {}",
												std::io::Error::from(std::io::ErrorKind::NotFound),
											)),

											Err(err) => Err(format!("could not get EST bootstrap identity cert: {}", err)),
										}
									}
									else {
										Err(format!(
											"cert {:?} is configured to be issued by EST, \
											but EST identity could not be obtained \
											and EST bootstrap identity is not configured; {}",
											id, identity_err,
										))
									};

								match bootstrap_identity {
									Ok((bootstrap_identity_cert, bootstrap_identity_private_key)) => {
										// Create a CSR for the new EST identity cert.

										let identity_key_pair_handle =
											server.key_client.create_key_pair_if_not_exists(identity_private_key, Some("ec-p256:rsa-4096:*"))
											.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

										let (identity_public_key, identity_private_key) = {
											let identity_key_pair_handle =
												std::ffi::CString::new(identity_key_pair_handle.0.clone())
												.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
											let identity_public_key =
												server.key_engine
												.load_public_key(&identity_key_pair_handle)
												.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
											let identity_private_key =
												server.key_engine
												.load_private_key(&identity_key_pair_handle)
												.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
											(identity_public_key, identity_private_key)
										};

										let mut identity_csr =
											openssl::x509::X509Req::builder()
											.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

										identity_csr.set_version(0).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

										let mut subject_name =
											openssl::x509::X509Name::builder()
											.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

										let common_name = cert_options.common_name.as_deref().unwrap_or("est-id");
										subject_name.append_entry_by_text("CN", common_name).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
										let subject_name = subject_name.build();
										identity_csr.set_subject_name(&subject_name).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

										let mut extensions =
											openssl::stack::Stack::new()
											.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
										let client_extension =
											openssl::x509::extension::ExtendedKeyUsage::new().client_auth().build()
											.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
										extensions
											.push(client_extension)
											.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
										identity_csr
											.add_extensions(&extensions)
											.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

										identity_csr.set_pubkey(&identity_public_key).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

										identity_csr
											.sign(&identity_private_key, openssl::hash::MessageDigest::sha256())
											.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

										let identity_csr = identity_csr.build();
										let identity_csr = identity_csr.to_pem().map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

										let identity_url =
											urls.get(identity_cert)
											.or_else(|| urls.get("default"))
											.ok_or_else(|| Error::Internal(InternalError::CreateCert(format!(
												"cert {:?} is configured to be issued by EST, but the EST endpoint URL for the EST identity is not configured",
												id,
											).into())))?;


										// Request the new EST identity cert using the EST bootstrap identity cert.

										let bootstrap_identity_private_key =
											std::ffi::CString::new(bootstrap_identity_private_key.0.clone())
											.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
										let bootstrap_identity_private_key =
											server.key_engine.load_private_key(&bootstrap_identity_private_key)
											.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

										let x509 = est::create_cert(
											identity_csr,
											identity_url,
											auth_basic,
											Some((&bootstrap_identity_cert, &bootstrap_identity_private_key)),
											trusted_certs_x509,
										).await?;

										let path = get_path(&server.homedir_path, &server.preloaded_certs, identity_cert)?;
										std::fs::write(path, &x509).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;


										// EST identity cert was obtained and persisted successfully. Now recurse to retry the original cert request.

										let x509 = create_cert(server, id, csr, issuer).await?;
										Ok(x509)
									},

									Err(bootstrap_identity_err) => {
										// Neither EST identity cert nor EST bootstrap identity cert could be obtained.
										Err(Error::Internal(InternalError::CreateCert(format!(
											"cert {:?} is configured to be issued by EST, but neither EST identity nor EST bootstrap identity could be obtained; \
											{} {}",
											id,
											identity_err,
											bootstrap_identity_err,
										).into())))
									},
								}
							},
						}
					}
					else {
						// We need to only use basic auth with the EST server.

						let x509 = est::create_cert(
							csr.to_owned(),
							url,
							auth_basic,
							None,
							trusted_certs_x509,
						).await?;

						let path = get_path(&server.homedir_path, &server.preloaded_certs, id)?;
						std::fs::write(path, &x509).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

						Ok(x509)
					}
				},

				config::CertIssuanceMethod::LocalCa => {
					// Indirect reference to the local CA. Look it up.

					let (issuer_cert, issuer_private_key) = match &server.cert_issuance.local_ca {
						Some(config::LocalCa { cert, pk }) => {
							let private_key = server.key_client.load_key_pair(pk).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
							(cert.clone(), private_key)
						},

						None => return Err(Error::Internal(InternalError::CreateCert(format!(
							"cert {:?} is configured to be issued by local CA, but local CA is not configured",
							id,
						).into()))),
					};


					// Recurse with the local CA set explicitly as the issuer parameter.

					let x509 = create_cert(server, id, csr, Some((&issuer_cert, &issuer_private_key))).await?;
					Ok(x509)
				},

				config::CertIssuanceMethod::SelfSigned => {
					// Since the client did not give us their private key handle, we assume that the key is named the same as the cert.
					//
					// TODO: Is there a way to not have to assume this?
					let key_pair_handle =
						server.key_client.load_key_pair(id)
						.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

					// Recurse with explicit issuer.
					let x509 = create_cert(server, id, csr, Some((id, &key_pair_handle))).await?;
					Ok(x509)
				},
			}
		}
	}

	Box::pin(create_cert_inner(server, id, csr, issuer))
}

fn get_cert_inner(
	homedir_path: &std::path::Path,
	preloaded_certs: &std::collections::BTreeMap<String, crate::config::PreloadedCert>,
	id: &str,
) -> Result<Option<Vec<u8>>, Error> {
	let path = get_path(homedir_path, preloaded_certs, id)?;
	let bytes = load_inner(&path)?;
	Ok(bytes)
}
