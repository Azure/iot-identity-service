#[derive(Debug, Clone, Copy)]
enum CertKind {
	DeviceId,
	DeviceCa,
	WorkloadCa,
	ModuleServer,
}

impl std::convert::TryFrom<crate::CERTGEN_CERT_KIND> for CertKind {
	type Error = ();

	fn try_from(cert_kind: crate::CERTGEN_CERT_KIND) -> Result<Self, Self::Error> {
		match cert_kind {
			crate::CERTGEN_CERT_KIND_DEVICE_ID => Ok(CertKind::DeviceId),
			crate::CERTGEN_CERT_KIND_DEVICE_CA => Ok(CertKind::DeviceCa),
			crate::CERTGEN_CERT_KIND_WORKLOAD_CA => Ok(CertKind::WorkloadCa),
			crate::CERTGEN_CERT_KIND_MODULE_SERVER => Ok(CertKind::ModuleServer),
			_ => Err(()),
		}
	}
}

lazy_static::lazy_static! {
	static ref HOMEDIR_PATH: std::sync::RwLock<Option<std::path::PathBuf>> = Default::default();
}

pub(crate) unsafe fn get_function_list(
	pfunction_list: *mut *const crate::CERTGEN_FUNCTION_LIST,
) -> crate::CERTGEN_ERROR {
	crate::r#catch(|| {
		static CERTGEN_FUNCTION_LIST: crate::CERTGEN_FUNCTION_LIST = crate::CERTGEN_FUNCTION_LIST {
			version: crate::CERTGEN_VERSION_2_0_0_0,

			set_parameter,
			create_or_load_cert,
			import_cert,
			delete_cert,
		};

		let mut function_list_out = std::ptr::NonNull::new(pfunction_list).ok_or_else(|| err_invalid_parameter("pfunction_list", "expected non-NULL"))?;
		*function_list_out.as_mut() = &CERTGEN_FUNCTION_LIST;
		Ok(())
	})
}

pub(crate) unsafe extern "C" fn set_parameter(
	name: *const std::os::raw::c_char,
	value: *const std::os::raw::c_char,
) -> crate::CERTGEN_ERROR {
	crate::r#catch(|| {
		let name = name.as_ref().ok_or_else(|| err_invalid_parameter("name", "expected non-NULL"))?;
		let name = std::ffi::CStr::from_ptr(name);
		let name = name.to_str().map_err(|err| err_invalid_parameter("name", err))?;

		match name {
			"HOMEDIR_PATH" => {
				let value = value.as_ref().ok_or_else(|| err_invalid_parameter("value", "expected non-NULL"))?;
				let value = std::ffi::CStr::from_ptr(value);
				let value = value.to_str().map_err(|err| err_invalid_parameter("value", err))?;
				let value: std::path::PathBuf = value.into();

				let mut guard = HOMEDIR_PATH.write().map_err(err_fatal)?;
				*guard = Some(value);
			},

			_ => return Err(err_invalid_parameter("name", "unrecognized value")),
		}

		Ok(())
	})
}

pub(crate) unsafe extern "C" fn create_or_load_cert(
	kind: crate::CERTGEN_CERT_KIND,
	uri: *const std::os::raw::c_char,
	public_key: *mut openssl_sys::EVP_PKEY,
	private_key: *mut openssl_sys::EVP_PKEY,
	pcert: *mut *mut openssl_sys::X509,
) -> crate::CERTGEN_ERROR {
	crate::r#catch(|| {
		let cert_kind: CertKind = std::convert::TryInto::try_into(kind).map_err(|()| err_invalid_parameter("kind", "unrecognized value"))?;

		let uri = match uri.as_ref() {
			Some(uri) => {
				let uri = std::ffi::CStr::from_ptr(uri);
				let uri = uri.to_str().map_err(|err| err_invalid_parameter("uri", err))?;
				let uri = uri.parse().map_err(|err| err_invalid_parameter("uri", err))?;
				Some(uri)
			},

			None => None,
		};

		let mut public_key = std::ptr::NonNull::new(public_key).ok_or_else(|| err_invalid_parameter("public_key", "expected non-NULL"))?;
		let public_key: &openssl::pkey::PKeyRef<openssl::pkey::Public> = foreign_types_shared::ForeignTypeRef::from_ptr(public_key.as_mut());

		let mut private_key = std::ptr::NonNull::new(private_key).ok_or_else(|| err_invalid_parameter("private_key", "expected non-NULL"))?;
		let private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private> = foreign_types_shared::ForeignTypeRef::from_ptr(private_key.as_mut());

		let mut cert_out = std::ptr::NonNull::new(pcert).ok_or_else(|| err_invalid_parameter("pcert", "expected non-NULL"))?;

		match uri {
			Some(Uri::File(cert_path)) => {
				let cert_pem = std::fs::read(cert_path).map_err(err_external)?;
				let cert = openssl::x509::X509::from_pem(&cert_pem)?;

				// Only run `foreign_type_into_ptr` after all fallible operations to ensure we don't leak any `EVP_PKEY`s
				*cert_out.as_mut() = openssl2::foreign_type_into_ptr(cert);

				Ok(())
			},

			None => {
				enum CertGenerationMethod {
					Filesystem { homedir_path: std::path::PathBuf },
				}

				// If HOMEDIR_PATH is set, use the filesystem for auto-generated certs.
				// Else, fail.
				let cert_generation_method = {
					let homedir_path = HOMEDIR_PATH.read().map_err(err_fatal)?;

					match &*homedir_path {
						Some(homedir_path) =>
							CertGenerationMethod::Filesystem { homedir_path: homedir_path.clone() },

						_ => return Err(err_invalid_parameter("uri", "unsupported scheme")),
					}
				};

				match cert_generation_method {
					#[allow(unreachable_code)] // TODO: Remove when all unimplemented!()s are resolved.
					CertGenerationMethod::Filesystem { homedir_path } => {
						// Default filenames based on the key kind
						let filename: std::borrow::Cow<'static, str> = match cert_kind {
							CertKind::DeviceId => "device-id.pem".into(),
							CertKind::DeviceCa => "device-ca.pem".into(),
							CertKind::WorkloadCa => "workload-ca.pem".into(),
							CertKind::ModuleServer => unimplemented!("TODO: where do we get the module ID from?"),
						};
						let mut full_path = homedir_path;
						full_path.push(&*filename);

						// Try to find the cert with the default filename first.

						let cert = match std::fs::read(&full_path) {
							Ok(cert_pem) => {
								let cert = openssl::x509::X509::from_pem(&cert_pem)?;
								cert
							},

							Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
								let mut builder = openssl::x509::X509::builder()?;

								builder.set_pubkey(public_key)?;

								// iotedged may override this. Eg for workload CA, it will clamp the not-after to the device CA cert's not-after.
								let (subject, not_after): (std::borrow::Cow<'static, str>, _) = match cert_kind {
									CertKind::DeviceId => return Err(err_invalid_parameter("kind", "device ID certs cannot be created, only loaded")),

									CertKind::DeviceCa => (
										"device-ca".into(),
										openssl::asn1::Asn1Time::days_from_now(90)?,
									),

									CertKind::WorkloadCa => (
										"workload-ca".into(),
										openssl::asn1::Asn1Time::days_from_now(90)?,
									),

									CertKind::ModuleServer => (
										unimplemented!("TODO: where do we get the module ID from?"),
										openssl::asn1::Asn1Time::days_from_now(30)?,
									),
								};
								builder.set_not_after(std::borrow::Borrow::borrow(&not_after))?;

								let not_before = openssl::asn1::Asn1Time::days_from_now(0)?;
								builder.set_not_before(std::borrow::Borrow::borrow(&not_before))?;

								let mut subject_name = openssl::x509::X509Name::builder()?;
								subject_name.append_entry_by_text("CN", &*subject)?;
								let subject_name = subject_name.build();
								builder.set_subject_name(&subject_name)?;

								match cert_kind {
									CertKind::DeviceId => return Err(err_invalid_parameter("kind", "device ID certs cannot be created, only loaded")),

									CertKind::DeviceCa => {
										let ca_extension =
											openssl::x509::extension::BasicConstraints::new()
											.ca()
											.build()?;
										builder.append_extension(ca_extension)?;

										builder.set_issuer_name(&subject_name)?;

										builder.sign(private_key, openssl::hash::MessageDigest::sha256())?;

										let cert = builder.build();

										let cert_pem = cert.to_pem()?;
										std::fs::write(&full_path, &cert_pem).map_err(err_external)?;

										cert
									},

									CertKind::WorkloadCa => {
										let ca_extension =
											openssl::x509::extension::BasicConstraints::new()
											.ca()
											.build()?;

										builder.append_extension(ca_extension)?;

										let cert = builder.build();
										cert
									},

									CertKind::ModuleServer => {
										let server_extension =
											openssl::x509::extension::ExtendedKeyUsage::new()
											.server_auth()
											.build()?;
										builder.append_extension(server_extension)?;

										// TODO: Is passing None for context valid? Does it lock the cert into self-signed?
										#[allow(unused_variables)] // TODO: Remove when unimplemented!() is resolved
										let context = builder.x509v3_context(None, None);
										#[allow(unused_variables)] // TODO: Remove when unimplemented!() is resolved
										let san_extension =
											openssl::x509::extension::SubjectAlternativeName::new()
											.dns(unimplemented!("TODO: where do we get the module ID from?"))
											.build(&context)?;
										builder.append_extension(san_extension)?;

										let cert = builder.build();
										cert
									},
								}
							},

							Err(err) => return Err(err_external(err)),
						};

						// Only run `foreign_type_into_ptr` after all fallible operations to ensure we don't leak any `EVP_PKEY`s
						*cert_out.as_mut() = openssl2::foreign_type_into_ptr(cert);

						Ok(())
					},
				}
			},
		}
	})
}

pub unsafe extern "C" fn import_cert(
	kind: crate::CERTGEN_CERT_KIND,
	uri: *const std::os::raw::c_char,
	cert: *mut openssl_sys::X509,
) -> crate::CERTGEN_ERROR {
	crate::r#catch(|| {
		let cert_kind: CertKind = std::convert::TryInto::try_into(kind).map_err(|()| err_invalid_parameter("kind", "unrecognized value"))?;

		let uri = match uri.as_ref() {
			Some(uri) => {
				let uri = std::ffi::CStr::from_ptr(uri);
				let uri = uri.to_str().map_err(|err| err_invalid_parameter("uri", err))?;
				let uri = uri.parse().map_err(|err| err_invalid_parameter("uri", err))?;
				Some(uri)
			},

			None => None,
		};

		let mut cert = std::ptr::NonNull::new(cert).ok_or_else(|| err_invalid_parameter("cert", "expected non-NULL"))?;
		let cert: &openssl::x509::X509Ref = foreign_types_shared::ForeignTypeRef::from_ptr(cert.as_mut());

		match uri {
			Some(Uri::File(cert_path)) => {
				let cert_pem = cert.to_pem()?;
				std::fs::write(cert_path, &cert_pem).map_err(err_external)?;

				Ok(())
			},

			None => {
				enum CertGenerationMethod {
					Filesystem { homedir_path: std::path::PathBuf },
				}

				// If HOMEDIR_PATH is set, use the filesystem for imported certs.
				// Else, fail.
				let cert_generation_method = {
					let homedir_path = HOMEDIR_PATH.read().map_err(err_fatal)?;

					match &*homedir_path {
						Some(homedir_path) =>
							CertGenerationMethod::Filesystem { homedir_path: homedir_path.clone() },

						_ => return Err(err_invalid_parameter("uri", "unsupported scheme")),
					}
				};

				match cert_generation_method {
					CertGenerationMethod::Filesystem { homedir_path } => {
						// Default filenames based on the key kind
						let filename: std::borrow::Cow<'static, str> = match cert_kind {
							CertKind::DeviceId => "device-id.pem".into(),
							CertKind::DeviceCa => "device-ca.pem".into(),
							CertKind::WorkloadCa => "workload-ca.pem".into(),
							CertKind::ModuleServer => unimplemented!("TODO: where do we get the module ID from?"),
						};
						let mut full_path = homedir_path;
						full_path.push(&*filename);

						let cert_pem = cert.to_pem()?;
						std::fs::write(&full_path, &cert_pem).map_err(err_external)?;

						Ok(())
					},
				}
			},
		}
	})
}

pub unsafe extern "C" fn delete_cert(
	kind: crate::CERTGEN_CERT_KIND,
	uri: *const std::os::raw::c_char,
) -> crate::CERTGEN_ERROR {
	crate::r#catch(|| {
		let cert_kind: CertKind = std::convert::TryInto::try_into(kind).map_err(|()| err_invalid_parameter("kind", "unrecognized value"))?;

		let uri = match uri.as_ref() {
			Some(uri) => {
				let uri = std::ffi::CStr::from_ptr(uri);
				let uri = uri.to_str().map_err(|err| err_invalid_parameter("uri", err))?;
				let uri = uri.parse().map_err(|err| err_invalid_parameter("uri", err))?;
				Some(uri)
			},

			None => None,
		};

		match uri {
			Some(Uri::File(cert_path)) => match std::fs::remove_file(cert_path) {
				Ok(()) => Ok(()),
				Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
				Err(err) => Err(err_external(err)),
			},

			None => {
				enum CertGenerationMethod {
					Filesystem { homedir_path: std::path::PathBuf },
				}

				// If HOMEDIR_PATH is set, use the filesystem for imported certs.
				// Else, fail.
				let cert_generation_method = {
					let homedir_path = HOMEDIR_PATH.read().map_err(err_fatal)?;

					match &*homedir_path {
						Some(homedir_path) =>
							CertGenerationMethod::Filesystem { homedir_path: homedir_path.clone() },

						_ => return Err(err_invalid_parameter("uri", "unsupported scheme")),
					}
				};

				match cert_generation_method {
					CertGenerationMethod::Filesystem { homedir_path } => {
						// Default filenames based on the key kind
						let filename: std::borrow::Cow<'static, str> = match cert_kind {
							CertKind::DeviceId => "device-id.pem".into(),
							CertKind::DeviceCa => "device-ca.pem".into(),
							CertKind::WorkloadCa => "workload-ca.pem".into(),
							CertKind::ModuleServer => unimplemented!("TODO: where do we get the module ID from?"),
						};
						let mut full_path = homedir_path;
						full_path.push(&*filename);

						match std::fs::remove_file(full_path) {
							Ok(()) => Ok(()),
							Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
							Err(err) => Err(err_external(err)),
						}
					},
				}
			},
		}
	})
}

#[derive(Debug)]
enum Uri {
	File(std::path::PathBuf),
}

impl std::str::FromStr for Uri {
	type Err = Box<dyn std::error::Error>;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let scheme_end_index = s.find(':').ok_or("missing scheme")?;
		let scheme = &s[..scheme_end_index];

		match scheme {
			"file" => {
				let uri: url::Url = s.parse()?;
				let path = uri.to_file_path().map_err(|()| "cannot convert to file path")?;
				Ok(Uri::File(path))
			},

			_ => Err("unrecognized scheme".into())
		}
	}
}

impl From<openssl::error::Error> for crate::CERTGEN_ERROR {
	fn from(err: openssl::error::Error) -> Self {
		err_external(err)
	}
}

impl From<openssl::error::ErrorStack> for crate::CERTGEN_ERROR {
	fn from(err: openssl::error::ErrorStack) -> Self {
		err_external(err)
	}
}

fn err_external<E>(err: E) -> crate::CERTGEN_ERROR where E: std::fmt::Display {
	eprintln!("{}", err);
	crate::CERTGEN_ERROR_EXTERNAL
}

fn err_fatal<E>(err: E) -> crate::CERTGEN_ERROR where E: std::fmt::Display {
	eprintln!("{}", err);
	crate::CERTGEN_ERROR_EXTERNAL
}

fn err_invalid_parameter<E>(name: &str, err: E) -> crate::CERTGEN_ERROR where E: std::fmt::Display {
	eprintln!("invalid parameter {:?}: {}", name, err);
	crate::CERTGEN_ERROR_INVALID_PARAMETER
}
