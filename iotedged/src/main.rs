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
	let Options {
		hub_id,
		device_id,
		preloaded_device_id_ca_cert,
		preloaded_device_id_cert,
		sas_key,
	} = structopt::StructOpt::from_args();


	let mut key_engine = {
		struct Connector;

		impl aziot_key_client::Connector for Connector {
			fn connect(&self) -> std::io::Result<Box<dyn aziot_key_client::Stream>> {
				let stream = std::net::TcpStream::connect(("localhost", 8888))?;
				Ok(Box::new(stream))
			}
		}

		let key_client = aziot_key_client::Client::new(Box::new(Connector));
		let key_client = std::sync::Arc::new(key_client);

		let key_engine = aziot_key_openssl_engine::load(key_client).map_err(Error::LoadKeyOpenslEngine)?;
		key_engine
	};

	let key_client = {
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

		let key_client = aziot_key_client_async::Client::new(Connector);
		let key_client = std::sync::Arc::new(key_client);
		key_client
	};

	let cert_client = {
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

		let cert_client = aziot_cert_client_async::Client::new(Connector);
		let cert_client = std::sync::Arc::new(cert_client);
		cert_client
	};


	// Device CA

	let device_ca_key_pair_handle =
		key_client.create_key_pair_if_not_exists("device-ca", Some("ec-p256:rsa-4096:*")).await.map_err(Error::CreateOrLoadDeviceCaKeyPair)?;
	let (device_ca_public_key, device_ca_private_key) = {
		let device_ca_key_pair_handle = std::ffi::CString::new(device_ca_key_pair_handle.0.clone()).unwrap();
		let device_ca_public_key = key_engine.load_public_key(&device_ca_key_pair_handle).unwrap();
		let device_ca_private_key = key_engine.load_private_key(&device_ca_key_pair_handle).unwrap();
		(device_ca_public_key, device_ca_private_key)
	};
	println!("Loaded device CA key with parameters: {}", Displayable(&*device_ca_public_key));

	let device_ca_cert = {
		let device_ca_cert = match cert_client.get_cert("device-ca").await {
			Ok(device_ca_cert) => device_ca_cert,
			Err(_) => {
				let csr =
					create_csr("device-ca", &device_ca_public_key, &device_ca_private_key)
					.map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;
				let device_ca_cert =
					cert_client.create_cert("device-ca", &csr, Some(("device-ca", &device_ca_key_pair_handle)))
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

		cert_client.delete_cert("device-ca").await.map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;

		let csr =
			create_csr("device-ca", &device_ca_public_key, &device_ca_private_key)
			.map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;
		let device_ca_cert =
			cert_client.create_cert("device-ca", &csr, Some(("device-ca", &device_ca_key_pair_handle)))
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
		key_client.create_key_pair_if_not_exists("workload-ca", Some("ec-p256:rsa-2048:*")).await.map_err(Error::CreateOrLoadWorkloadCaKeyPair)?;
	let (workload_ca_public_key, workload_ca_private_key) = {
		let workload_ca_key_pair_handle = std::ffi::CString::new(workload_ca_key_pair_handle.0.clone()).unwrap();
		let workload_ca_public_key = key_engine.load_public_key(&workload_ca_key_pair_handle).unwrap();
		let workload_ca_private_key = key_engine.load_private_key(&workload_ca_key_pair_handle).unwrap();
		(workload_ca_public_key, workload_ca_private_key)
	};

	println!("Loaded workload CA key with parameters: {}", Displayable(&*workload_ca_public_key));

	let workload_ca_cert = {
		let workload_ca_cert = match cert_client.get_cert("workload-ca").await {
			Ok(workload_ca_cert) => workload_ca_cert,
			Err(_) => {
				let csr =
					create_csr("workload-ca", &workload_ca_public_key, &workload_ca_private_key)
					.map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;
				let workload_ca_cert =
					cert_client.create_cert("workload-ca", &csr, Some(("device-ca", &device_ca_key_pair_handle)))
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

		cert_client.delete_cert("workload-ca").await.map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;

		let csr =
			create_csr("workload-ca", &workload_ca_public_key, &workload_ca_private_key)
			.map_err(|err| Error::CreateOrLoadWorkloadCaCert(Box::new(err)))?;
		let workload_ca_cert =
			cert_client.create_cert("workload-ca", &csr, Some(("device-ca", &device_ca_key_pair_handle)))
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


	let mut request: hyper::Request<hyper::Body> = hyper::Request::new(Default::default());
	*request.uri_mut() =
		format!(
			"https://{}/devices/{}/modules?api-version=2017-11-08-preview",
			hub_id,
			percent_encoding::percent_encode(device_id.as_bytes(), IOTHUB_ENCODE_SET),
		)
		.parse().unwrap();

	let client =
		if let Some(key) = sas_key {
			println!("Using SAS key auth");


			let key_handle = {
				let key = base64::decode(key).unwrap();
				key_client.create_key_if_not_exists("device-id", aziot_key_common::CreateKeyValue::Import { bytes: key }).await.unwrap()
			};


			// Verify encrypt-decrypt

			let mut rng = rand::rngs::OsRng;

			let original_plaintext = b"aaaaaa";
			let iv = {
				let mut iv = vec![0_u8; 16];
				rand::RngCore::fill_bytes(&mut rng, &mut iv);
				iv
			};
			let aad = b"$iotedged".to_vec();

			let ciphertext = key_client.encrypt(&key_handle, aziot_key_common::EncryptMechanism::Aead { iv: iv.clone(), aad: aad.clone() }, original_plaintext).await.unwrap();

			let new_plaintext = key_client.decrypt(&key_handle, aziot_key_common::EncryptMechanism::Aead { iv, aad }, &ciphertext).await.unwrap();
			assert_eq!(original_plaintext, &new_plaintext[..]);


			// Verify IoT Hub auth using SAS key

			let token = {
				let expiry = chrono::Utc::now() + chrono::Duration::from_std(std::time::Duration::from_secs(30)).unwrap();
				let expiry = expiry.timestamp().to_string();
				let audience = format!("{}/devices/{}", hub_id, device_id);

				let resource_uri = percent_encoding::percent_encode(audience.to_lowercase().as_bytes(), IOTHUB_ENCODE_SET).to_string();
				let sig_data = format!("{}\n{}", &resource_uri, expiry);

				let signature = key_client.sign(&key_handle, aziot_key_common::SignMechanism::HmacSha256, sig_data.as_bytes()).await.unwrap();
				let signature = base64::encode(&signature);

				let token =
					url::form_urlencoded::Serializer::new(format!("sr={}", resource_uri))
					.append_pair("sig", &signature)
					.append_pair("se", &expiry)
					.finish();
				token
			};
			println!("{}", token);

			let authorization_header_value = hyper::header::HeaderValue::from_str(&format!("SharedAccessSignature {}", token)).unwrap();
			request.headers_mut().append(hyper::header::AUTHORIZATION, authorization_header_value);

			let tls_connector = hyper_openssl::HttpsConnector::new().unwrap();

			let client = hyper::Client::builder().build(tls_connector);
			client
		}
		else {
			let device_id: std::borrow::Cow<'static, str> =
				if let Some(preloaded_device_id_cert) = preloaded_device_id_cert {
					println!("Using X.509 auth with preloaded device ID cert");
					preloaded_device_id_cert.into()
				}
				else if let Some(preloaded_device_id_ca_cert) = preloaded_device_id_ca_cert {
					println!("Using X.509 auth with new device ID cert");

					let device_id_ca_key_handle = key_client.load_key_pair(&preloaded_device_id_ca_cert).await.unwrap();

					let device_id = "device-id";

					let device_id_key_pair_handle =
						key_client.create_key_pair_if_not_exists(device_id, Some("ec-p256:rsa-4096:*")).await.unwrap();
					let (device_id_public_key, device_id_private_key) = {
						let device_id_key_pair_handle = std::ffi::CString::new(device_id_key_pair_handle.0.clone()).unwrap();
						let device_id_public_key = key_engine.load_public_key(&device_id_key_pair_handle).unwrap();
						let device_id_private_key = key_engine.load_private_key(&device_id_key_pair_handle).unwrap();
						(device_id_public_key, device_id_private_key)
					};

					let csr =
						create_csr(device_id, &device_id_public_key, &device_id_private_key)
						.map_err(|err| Error::CreateOrLoadDeviceCaCert(Box::new(err)))?;
					let device_id_cert =
						cert_client.create_cert(device_id, &csr, Some((&preloaded_device_id_ca_cert, &device_id_ca_key_handle))).await.unwrap();
					let _ = openssl::x509::X509::stack_from_pem(&device_id_cert).unwrap();

					device_id.into()
				}
				else {
					unreachable!("clap should not allow the code to reach here");
				};

			let mut tls_connector = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()).unwrap();

			let device_id_private_key = {
				let device_id_key_handle = key_client.load_key_pair(&device_id).await.unwrap();
				let device_id_key_handle = std::ffi::CString::new(device_id_key_handle.0).unwrap();
				let device_id_private_key = key_engine.load_private_key(&device_id_key_handle).unwrap();
				device_id_private_key
			};
			tls_connector.set_private_key(&device_id_private_key).unwrap();

			let mut device_id_certs = {
				let device_id_certs = cert_client.get_cert(&device_id).await.unwrap();
				let device_id_certs = openssl::x509::X509::stack_from_pem(&device_id_certs).unwrap().into_iter();
				device_id_certs
			};
			let client_cert = device_id_certs.next().unwrap();
			tls_connector.set_certificate(&client_cert).unwrap();
			for cert in device_id_certs {
				tls_connector.add_extra_chain_cert(cert).unwrap();
			}

			let mut http_connector = hyper::client::HttpConnector::new();
			http_connector.enforce_http(false);
			let tls_connector = hyper_openssl::HttpsConnector::with_connector(http_connector, tls_connector).unwrap();

			let client = hyper::Client::builder().build(tls_connector);
			client
		};

	println!("{:?}", request);
	let response = client.request(request).await.unwrap();
	assert_eq!(response.status(), hyper::StatusCode::OK);
	let response = response.into_body();
	let response = hyper::body::to_bytes(response).await.unwrap();
	let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
	println!("{:#?}", response);


	Ok(())
}

#[derive(structopt::StructOpt)]
#[structopt(group = structopt::clap::ArgGroup::with_name("auth_method").required(true))]
struct Options {
	/// IoT Hub ID, eg "example.azure-devices.net"
	#[structopt(long)]
	hub_id: String,

	/// IoT device ID, eg "example-1"
	#[structopt(long)]
	device_id: String,

	/// ID of a device ID CA cert that has been preloaded into the KS and CS.
	///
	/// The program will generate a device ID cert signed from this CA cert to authenticate to IoT Hub.
	#[structopt(long, group = "auth_method")]
	preloaded_device_id_ca_cert: Option<String>,

	/// ID of a device ID cert that has been preloaded into the KS and CS.
	///
	/// The program will use this cert to authenticate to IoT Hub.
	#[structopt(long, group = "auth_method")]
	preloaded_device_id_cert: Option<String>,

	/// A SAS key, in base64 encoding.
	///
	/// The program will import this key into the KS and use it to authenticate to IoT Hub.
	#[structopt(long, group = "auth_method")]
	sas_key: Option<String>,
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
	LoadKeyOpenslEngine(openssl2::Error),
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
			Error::LoadKeyOpenslEngine(_) => f.write_str("could not load aziot-key-openssl-engine"),
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
			Error::LoadKeyOpenslEngine(err) => Some(err),
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
