#![deny(rust_2018_idioms, warnings)]
#![allow(
	clippy::let_and_return,
)]

mod error;
pub use error::{Error, InternalError};

pub struct Server {
	homedir_path: std::path::PathBuf,
	key_engine: std::sync::Arc<std::sync::Mutex<openssl2::FunctionalEngine>>,
}

impl Server {
	pub fn new(
		homedir_path: std::path::PathBuf,
		key_client: std::sync::Arc<aziot_key_client::Client>,
	) -> Result<Self, Error> {
		let key_engine = aziot_key_openssl_engine::load(key_client).map_err(|err| Error::Internal(InternalError::LoadKeyOpenslEngine(err)))?;
		let key_engine = std::sync::Arc::new(std::sync::Mutex::new(key_engine));

		Ok(Server {
			homedir_path,
			key_engine,
		})
	}
}

impl Server {
	pub fn create_cert(
		&self,
		id: &str,
		csr: &[u8],
		issuer: Option<(&str, &aziot_key_common::KeyHandle)>,
	) -> Result<Vec<u8>, Error> {
		if let Some((issuer_id, issuer_private_key)) = issuer {
			let x509_req = openssl::x509::X509Req::from_pem(csr).map_err(|err| Error::invalid_parameter("csr", err))?;
			let x509_req_public_key = x509_req.public_key().map_err(|err| Error::invalid_parameter("csr", err))?;
			if !x509_req.verify(&x509_req_public_key).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))? {
				return Err(Error::invalid_parameter("csr", "CSR failed to be verified with its public key"));
			}

			let mut x509 = openssl::x509::X509::builder().map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
			x509.set_subject_name(x509_req.subject_name()).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
			x509.set_pubkey(&x509_req_public_key).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

			x509.set_not_before(
				&*openssl::asn1::Asn1Time::days_from_now(0)
				.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?
			).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
			x509.set_not_after(
				&*openssl::asn1::Asn1Time::days_from_now(30)
				.map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?
			).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

			// TODO: Copy key usage from x509_req to x509
			//
			// Requires enumerating x509_req.extensions(), but X509Extension is opaque?!
			let ca_extension =
				openssl::x509::extension::BasicConstraints::new()
				.ca()
				.build().map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
			x509.append_extension(ca_extension).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

			let mut key_engine = self.key_engine.lock().expect("ks engine mutex poisoned");
			let key_engine = &mut *key_engine;

			let issuer_private_key =
				std::ffi::CString::new(issuer_private_key.0.clone()).map_err(|err| Error::invalid_parameter("issuer.privateKeyHandle", err))?;
			let issuer_private_key =
				key_engine.load_private_key(&issuer_private_key).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

			let x509 =
				if issuer_id == id {
					x509.sign(&issuer_private_key, openssl::hash::MessageDigest::sha256()).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

					let x509 = x509.build();

					let x509 = x509.to_pem().map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;
					x509
				}
				else {
					let issuer_path = get_path(&self.homedir_path, issuer_id)?;
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

			let path = get_path(&self.homedir_path, id)?;
			std::fs::write(path, &x509).map_err(|err| Error::Internal(InternalError::CreateCert(Box::new(err))))?;

			Ok(x509)
		}
		else {
			// TODO: Issuer is not needed if the cert is to be issued externally, like from DPS or EST.
			Err(Error::invalid_parameter("issuer", "issuer is required for locally-issued certs"))
		}
	}

	pub fn import_cert(
		&self,
		id: &str,
		pem: &[u8],
	) -> Result<(), Error> {
		let path = get_path(&self.homedir_path, id)?;
		create_inner(&path, pem)?;
		Ok(())
	}

	pub fn get_cert(
		&self,
		id: &str,
	) -> Result<Vec<u8>, Error> {
		let path = get_path(&self.homedir_path, id)?;
		let bytes = load_inner(&path)?.ok_or_else(|| Error::invalid_parameter("id", "not found"))?;
		Ok(bytes)
	}

	pub fn delete_cert(
		&self,
		id: &str,
	) -> Result<(), Error> {
		let path = get_path(&self.homedir_path, id)?;
		match std::fs::remove_file(path) {
			Ok(()) => Ok(()),
			Err(ref err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
			Err(err) => Err(Error::Internal(InternalError::DeleteFile(err))),
		}
	}
}

fn get_path(homedir_path: &std::path::Path, cert_id: &str) -> Result<std::path::PathBuf, Error> {
	let mut path = homedir_path.to_owned();

	let filename =
		openssl::hash::hash(openssl::hash::MessageDigest::sha256(), cert_id.as_bytes())
		.map_err(|err| Error::Internal(InternalError::GetPath(err)))?;
	let filename = hex::encode(filename);
	path.push(format!("{}.cer", filename));

	Ok(path)
}

fn load_inner(path: &std::path::Path) -> Result<Option<Vec<u8>>, Error> {
	match std::fs::read(path) {
		Ok(cert_bytes) => Ok(Some(cert_bytes)),
		Err(ref err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
		Err(err) => Err(Error::Internal(InternalError::ReadFile(err))),
	}
}

fn create_inner(path: &std::path::Path, bytes: &[u8]) -> Result<(), Error> {
	std::fs::write(path, bytes).map_err(|err| Error::Internal(InternalError::CreateFile(err)))?;
	Ok(())
}
