#![deny(rust_2018_idioms, warnings)]
#![allow(
	clippy::let_and_return,
	clippy::type_complexity,
)]

const IOTHUB_ENCODE_SET: &percent_encoding::AsciiSet =
	&http_common::PATH_SEGMENT_ENCODE_SET
	.add(b'=');

#[tokio::main]
async fn main() -> Result<(), Error> {
	let mut ks_engine = {
		struct Connector;

		impl ks_client::Connector for Connector {
			fn connect(&self) -> std::io::Result<Box<dyn ks_client::Stream>> {
				let stream = std::net::TcpStream::connect(("localhost", 8888))?;
				Ok(Box::new(stream))
			}
		}

		let ks_client = ks_client::Client::new(Box::new(Connector));
		let ks_client = std::sync::Arc::new(ks_client);

		let ks_engine = openssl_engine_ks::load(ks_client).map_err(Error::LoadKeysServiceOpensslEngine)?;
		ks_engine
	};

	let ks_client = {
		#[derive(Clone, Copy)]
		struct Connector;

		impl hyper::service::Service<hyper::Uri> for Connector {
			type Response = tokio::net::TcpStream;
			type Error = std::io::Error;
			type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

			fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
				std::task::Poll::Ready(Ok(()))
			}

			fn call(&mut self, _req: hyper::Uri) -> Self::Future {
				let f = async {
					let stream = tokio::net::TcpStream::connect(("localhost", 8888)).await?;
					Ok(stream)
				};
				Box::pin(f)
			}
		}

		let ks_client = ks_client_async::Client::new(Connector);
		let ks_client = std::sync::Arc::new(ks_client);
		ks_client
	};

	let cs_client = {
		#[derive(Clone, Copy)]
		struct Connector;

		impl hyper::service::Service<hyper::Uri> for Connector {
			type Response = tokio::net::TcpStream;
			type Error = std::io::Error;
			type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

			fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
				std::task::Poll::Ready(Ok(()))
			}

			fn call(&mut self, _req: hyper::Uri) -> Self::Future {
				let f = async {
					let stream = tokio::net::TcpStream::connect(("localhost", 8889)).await?;
					Ok(stream)
				};
				Box::pin(f)
			}
		}

		let cs_client = cs_client_async::Client::new(Connector);
		let cs_client = std::sync::Arc::new(cs_client);
		cs_client
	};


	// Device CA

	let device_ca_key_pair_handle =
		ks_client.create_key_pair_if_not_exists("device-ca", Some("ec-p256:rsa-4096:*")).await.map_err(Error::CreateOrLoadDeviceCaKeyPair)?;
	let (device_ca_public_key, device_ca_private_key) = {
		let device_ca_key_pair_handle = std::ffi::CString::new(device_ca_key_pair_handle.0.clone()).unwrap();
		let device_ca_public_key = ks_engine.load_public_key(&device_ca_key_pair_handle).unwrap();
		let device_ca_private_key = ks_engine.load_private_key(&device_ca_key_pair_handle).unwrap();
		(device_ca_public_key, device_ca_private_key)
	};
	println!("Loaded device CA key with parameters: {}", Displayable(&*device_ca_public_key));

	let device_ca_cert = {
		let device_ca_cert = match cs_client.get_cert("device-ca").await {
			Ok(device_ca_cert) => device_ca_cert,
			Err(_) => {
				let csr =
					create_csr("device-ca", &device_ca_public_key, &device_ca_private_key)
					.map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;
				let device_ca_cert =
					cs_client.create_cert("device-ca", &csr, Some(("device-ca", &device_ca_key_pair_handle)))
					.await.map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;
				device_ca_cert
			},
		};
		let device_ca_cert = openssl::x509::X509::stack_from_pem(&device_ca_cert).map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;
		device_ca_cert
	};
	println!("Loaded device CA cert with parameters: {}", Displayable(&*device_ca_cert));
	let regenerate_device_ca_cert = match verify_device_ca_cert(&device_ca_cert[0], &device_ca_private_key)? {
		VerifyDeviceCaCertResult::Ok => false,

		VerifyDeviceCaCertResult::MismatchedKeys => {
			println!("Device CA cert does not match device CA private key.");
			true
		},
	};
	if regenerate_device_ca_cert {
		println!("Generating new device CA cert...");

		cs_client.delete_cert("device-ca").await.map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;

		let csr =
			create_csr("device-ca", &device_ca_public_key, &device_ca_private_key)
			.map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;
		let device_ca_cert =
			cs_client.create_cert("device-ca", &csr, Some(("device-ca", &device_ca_key_pair_handle)))
			.await.map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;
		let device_ca_cert = openssl::x509::X509::stack_from_pem(&device_ca_cert).map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;

		println!("Loaded device CA cert with parameters: {}", Displayable(&*device_ca_cert));
		match verify_device_ca_cert(&device_ca_cert[0], &device_ca_private_key)? {
			VerifyDeviceCaCertResult::Ok => (),

			verify_result => {
				// TODO: Handle properly
				panic!("new device CA cert still failed to validate: {:?}", verify_result);
			},
		}
	}


	// Workload CA

	let workload_ca_key_pair_handle =
		ks_client.create_key_pair_if_not_exists("workload-ca", Some("ec-p256:rsa-2048:*")).await.map_err(Error::CreateOrLoadWorkloadCaKeyPair)?;
	let (workload_ca_public_key, workload_ca_private_key) = {
		let workload_ca_key_pair_handle = std::ffi::CString::new(workload_ca_key_pair_handle.0.clone()).unwrap();
		let workload_ca_public_key = ks_engine.load_public_key(&workload_ca_key_pair_handle).unwrap();
		let workload_ca_private_key = ks_engine.load_private_key(&workload_ca_key_pair_handle).unwrap();
		(workload_ca_public_key, workload_ca_private_key)
	};

	println!("Loaded workload CA key with parameters: {}", Displayable(&*workload_ca_public_key));

	let workload_ca_cert = {
		let workload_ca_cert = match cs_client.get_cert("workload-ca").await {
			Ok(workload_ca_cert) => workload_ca_cert,
			Err(_) => {
				let csr =
					create_csr("workload-ca", &workload_ca_public_key, &workload_ca_private_key)
					.map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;
				let workload_ca_cert =
					cs_client.create_cert("workload-ca", &csr, Some(("device-ca", &device_ca_key_pair_handle)))
					.await.map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;
				workload_ca_cert
			},
		};
		let workload_ca_cert = openssl::x509::X509::stack_from_pem(&workload_ca_cert).map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;
		workload_ca_cert
	};
	println!("Loaded workload CA cert with parameters: {}", Displayable(&*workload_ca_cert));
	let regenerate_workload_ca_cert = match verify_workload_ca_cert(&workload_ca_cert[0], &workload_ca_private_key, &device_ca_cert[0], &device_ca_public_key)? {
		VerifyWorkloadCaCertResult::Ok => false,

		VerifyWorkloadCaCertResult::MismatchedKeys => {
			println!("Workload CA cert does not match workload CA private key.");
			true
		},

		VerifyWorkloadCaCertResult::NotSignedByDeviceCa => {
			println!("Workload CA cert is not signed by device CA cert.");
			true
		},
	};
	if regenerate_workload_ca_cert {
		println!("Generating new workload CA cert...");

		cs_client.delete_cert("workload-ca").await.map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;

		let csr =
			create_csr("workload-ca", &workload_ca_public_key, &workload_ca_private_key)
			.map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;
		let workload_ca_cert =
			cs_client.create_cert("workload-ca", &csr, Some(("device-ca", &device_ca_key_pair_handle)))
			.await.map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;
		let workload_ca_cert = openssl::x509::X509::stack_from_pem(&*workload_ca_cert).map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;

		println!("Loaded workload CA cert with parameters: {}", Displayable(&*workload_ca_cert));
		match verify_workload_ca_cert(&workload_ca_cert[0], &workload_ca_private_key, &device_ca_cert[0], &device_ca_public_key)? {
			VerifyWorkloadCaCertResult::Ok => (),

			verify_result => {
				// TODO: Handle properly
				panic!("new workload CA cert still failed to validate: {:?}", verify_result);
			},
		}
	}


	// Verify IoT Hub auth using SAS key

	let (hub_id, device_id, key) = (
		std::env::var("HUB_ID").unwrap(),
		std::env::var("DEVICE_ID").unwrap(),
		std::env::var("SAS_KEY").unwrap(),
	);
	let key_handle = {
		let key = base64::decode(key).unwrap();
		ks_client.create_key_if_not_exists("device-id", ks_common::CreateKeyValue::Import { bytes: key }).await.unwrap()
	};
	let token = {
		let expiry = chrono::Utc::now() + chrono::Duration::from_std(std::time::Duration::from_secs(30)).unwrap();
		let expiry = expiry.timestamp().to_string();
		let audience = format!("{}/devices/{}", hub_id, device_id);

		let resource_uri = percent_encoding::percent_encode(audience.to_lowercase().as_bytes(), IOTHUB_ENCODE_SET).to_string();
		let sig_data = format!("{}\n{}", &resource_uri, expiry);

		let signature = ks_client.sign(&key_handle, ks_common::SignMechanism::HmacSha256, sig_data.as_bytes()).await.unwrap();
		let signature = base64::encode(&signature);

		let token =
			url::form_urlencoded::Serializer::new(format!("sr={}", resource_uri))
			.append_pair("sig", &signature)
			.append_pair("se", &expiry)
			.finish();
		token
	};
	println!("{}", token);

	let authorization_header_value = reqwest::header::HeaderValue::from_str(&format!("SharedAccessSignature {}", token)).unwrap();
	let mut default_headers = reqwest::header::HeaderMap::new();
	default_headers.insert(reqwest::header::AUTHORIZATION, authorization_header_value);

	let client =
		reqwest::Client::builder()
		.default_headers(default_headers)
		.build()
		.unwrap();
	let url = format!("https://{}/devices/{}/modules?api-version=2017-11-08-preview", hub_id, percent_encoding::percent_encode(device_id.as_bytes(), IOTHUB_ENCODE_SET));
	let response: serde_json::Value = client.get(&url).send().await.unwrap().json().await.unwrap();
	println!("{:#?}", response);


	// Verify encrypt-decrypt

	let mut rng = rand::rngs::OsRng;

	let original_plaintext = b"aaaaaa";
	let iv = {
		let mut iv = vec![0_u8; 16];
		rand::RngCore::fill_bytes(&mut rng, &mut iv);
		iv
	};
	let aad = b"$iotedged".to_vec();

	let ciphertext = ks_client.encrypt(&key_handle, ks_common::EncryptMechanism::Aead { iv: iv.clone(), aad: aad.clone() }, original_plaintext).await.unwrap();

	let new_plaintext = ks_client.decrypt(&key_handle, ks_common::EncryptMechanism::Aead { iv, aad }, &ciphertext).await.unwrap();
	assert_eq!(original_plaintext, &new_plaintext[..]);

	Ok(())
}

fn cert_public_key_matches_private_key(
	cert: &openssl::x509::X509Ref,
	private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> bool {
	unsafe {
		openssl2::openssl_returns_1(openssl_sys2::X509_check_private_key(
			foreign_types_shared::ForeignTypeRef::as_ptr(cert),
			foreign_types_shared::ForeignTypeRef::as_ptr(private_key),
		)).is_ok()
	}
}

fn create_csr(
	subject: &str,
	public_key: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
	private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
	let mut csr = openssl::x509::X509Req::builder()?;

	csr.set_version(0)?;

	let mut subject_name = openssl::x509::X509Name::builder()?;
	subject_name.append_entry_by_text("CN", subject)?;
	let subject_name = subject_name.build();
	csr.set_subject_name(&subject_name)?;

	csr.set_pubkey(public_key)?;

	csr.sign(private_key, openssl::hash::MessageDigest::sha256())?;

	let csr = csr.build();
	let csr = csr.to_pem()?;
	Ok(csr)
}

fn verify_device_ca_cert(
	device_ca_cert: &openssl::x509::X509Ref,
	device_ca_private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
) -> Result<VerifyDeviceCaCertResult, Error> {
	if !cert_public_key_matches_private_key(device_ca_cert, device_ca_private_key) {
		return Ok(VerifyDeviceCaCertResult::MismatchedKeys);
	}

	Ok(VerifyDeviceCaCertResult::Ok)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifyDeviceCaCertResult {
	Ok,
	MismatchedKeys,
}

fn verify_workload_ca_cert(
	workload_ca_cert: &openssl::x509::X509Ref,
	workload_ca_private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
	device_ca_cert: &openssl::x509::X509Ref,
	device_ca_public_key: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
) -> Result<VerifyWorkloadCaCertResult, Error> {
	if !cert_public_key_matches_private_key(workload_ca_cert, workload_ca_private_key) {
		return Ok(VerifyWorkloadCaCertResult::MismatchedKeys);
	}

	if workload_ca_cert.signature().as_slice().is_empty() {
		return Ok(VerifyWorkloadCaCertResult::NotSignedByDeviceCa);
	}

	if !workload_ca_cert.verify(device_ca_public_key).map_err(Error::VerifyWorkloadCaCert)? {
		return Ok(VerifyWorkloadCaCertResult::NotSignedByDeviceCa);
	}

	if device_ca_cert.issued(workload_ca_cert) != openssl::x509::X509VerifyResult::OK {
		return Ok(VerifyWorkloadCaCertResult::NotSignedByDeviceCa);
	}

	Ok(VerifyWorkloadCaCertResult::Ok)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VerifyWorkloadCaCertResult {
	Ok,
	MismatchedKeys,
	NotSignedByDeviceCa,
}

enum Error {
	CreateOrLoadDeviceCaCert(Box<dyn std::error::Error>),
	CreateOrLoadDeviceCaKeyPair(std::io::Error),
	CreateOrLoadWorkloadCaCert(Box<dyn std::error::Error>),
	CreateOrLoadWorkloadCaKeyPair(std::io::Error),
	LoadKeysServiceOpensslEngine(openssl2::Error),
	VerifyWorkloadCaCert(openssl::error::ErrorStack),
}

impl std::fmt::Debug for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		writeln!(f, "{}", self)?;

		let mut source = std::error::Error::source(self);
		while let Some(err) = source {
			writeln!(f, "caused by: {}", err)?;
			source = err.source();
		}

		Ok(())
	}
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Error::CreateOrLoadDeviceCaCert(_) => f.write_str("could not create device CA cert"),
			Error::CreateOrLoadDeviceCaKeyPair(_) => f.write_str("could not create or load device CA key pair"),
			Error::CreateOrLoadWorkloadCaCert(_) => f.write_str("could not create workload CA cert"),
			Error::CreateOrLoadWorkloadCaKeyPair(_) => f.write_str("could not create or load workload CA key pair"),
			Error::LoadKeysServiceOpensslEngine(_) => f.write_str("could not load keys service openssl engine"),
			Error::VerifyWorkloadCaCert(_) => f.write_str("could not verify workload CA cert signature"),
		}
	}
}

impl std::error::Error for Error {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Error::CreateOrLoadDeviceCaCert(err) => Some(&**err),
			Error::CreateOrLoadDeviceCaKeyPair(err) => Some(err),
			Error::CreateOrLoadWorkloadCaCert(err) => Some(&**err),
			Error::CreateOrLoadWorkloadCaKeyPair(err) => Some(err),
			Error::LoadKeysServiceOpensslEngine(err) => Some(err),
			Error::VerifyWorkloadCaCert(err) => Some(err),
		}
	}
}

// TODO: Would like to write `struct Displayable<'a, T>(&'a T) where T: ?Sized;`, but that raises a bogus warning
// as described in https://github.com/rust-lang/rust/issues/60993
struct Displayable<'a, T: ?Sized>(&'a T);

impl<T> std::fmt::Display for Displayable<'_, openssl::pkey::PKeyRef<T>> where T: openssl::pkey::HasPublic {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		if let Ok(ec_key) = self.0.ec_key() {
			std::fmt::Display::fmt(&Displayable(&*ec_key), f)
		}
		else if let Ok(rsa) = self.0.rsa() {
			std::fmt::Display::fmt(&Displayable(&*rsa), f)
		}
		else {
			f.write_str("<unknown type>")
		}
	}
}

impl<T> std::fmt::Display for Displayable<'_, openssl::ec::EcKeyRef<T>> where T: openssl::pkey::HasPublic {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let group = self.0.group();
		let curve_name = group.curve_name().map(|nid| nid.long_name()).transpose()?.unwrap_or("<unknown>");

		let mut big_num_context = openssl::bn::BigNumContext::new()?;
		let point = self.0.public_key();
		let point = point.to_bytes(group, openssl::ec::PointConversionForm::UNCOMPRESSED, &mut big_num_context)?;

		write!(f, "EC, curve = {}, point = 0x", curve_name)?;
		for b in point {
			write!(f, "{:02x}", b)?;
		}

		Ok(())
	}
}

impl<T> std::fmt::Display for Displayable<'_, openssl::rsa::RsaRef<T>> where T: openssl::pkey::HasPublic {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let modulus = self.0.n();

		let exponent = self.0.e();

		write!(f, "RSA, modulus = 0x{} ({} bits), exponent = {}", modulus.to_hex_str()?, modulus.num_bits(), exponent)?;

		Ok(())
	}
}

impl std::fmt::Display for Displayable<'_, openssl::x509::X509Ref> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		let subject_name =
			self.0.subject_name().entries().next()
			.ok_or(())
			.and_then(|entry| entry.data().as_utf8().map_err(|_| ()))
			.map(|s| s.to_string())
			.unwrap_or_else(|_| String::new());

		let issuer_name =
			self.0.issuer_name().entries().next()
			.ok_or(())
			.and_then(|entry| entry.data().as_utf8().map_err(|_| ()))
			.map(|s| s.to_string())
			.unwrap_or_else(|_| String::new());

		let digest: std::borrow::Cow<'static, str> = match self.0.digest(openssl::hash::MessageDigest::sha256()) {
			Ok(digest_bytes) => {
				let mut digest = String::new();
				for &b in digest_bytes.as_ref() {
					digest.push_str(&format!("{:02x}", b));
				}
				digest.into()
			},
			Err(_) => "<error>".into(),
		};

		write!(f, "subject name = {:?}, issuer_name = {:?}, digest = {}", subject_name, issuer_name, digest)?;

		Ok(())
	}
}

impl std::fmt::Display for Displayable<'_, [openssl::x509::X509]> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		for cert in self.0 {
			Displayable(&**cert).fmt(f)?;
		}

		Ok(())
	}
}
