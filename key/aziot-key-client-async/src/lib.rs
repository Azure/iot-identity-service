#![deny(rust_2018_idioms, warnings)]
#![allow(
	clippy::let_and_return,
)]

pub struct Client<C> {
	inner: hyper::Client<C, hyper::Body>,
}

impl<C> Client<C> where C: hyper::client::connect::Connect + Clone {
	pub fn new(connect: C) -> Self {
		let inner = hyper::Client::builder().build(connect);
		Client {
			inner,
		}
	}
}

impl<C> std::fmt::Debug for Client<C> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Client").finish()
	}
}

impl<C> Client<C> where C: hyper::client::connect::Connect + Clone + Send + Sync + 'static {
	pub async fn create_key_pair_if_not_exists(
		&self,
		id: &str,
		preferred_algorithms: Option<&str>,
	) -> Result<aziot_key_common::KeyHandle, std::io::Error> {
		let body = aziot_key_common_http::create_key_pair_if_not_exists::Request {
			id: id.to_owned(),
			preferred_algorithms: preferred_algorithms.map(ToOwned::to_owned),
		};

		let res: aziot_key_common_http::create_key_pair_if_not_exists::Response = request(
			&self.inner,
			http::Method::POST,
			"/keypair",
			Some(&body),
		).await?;
		Ok(res.handle)
	}

	pub async fn load_key_pair(
		&self,
		id: &str,
	) -> Result<aziot_key_common::KeyHandle, std::io::Error> {
		let uri = format!("/keypair/{}", percent_encoding::percent_encode(id.as_bytes(), http_common::PATH_SEGMENT_ENCODE_SET));

		let res: aziot_key_common_http::load_key_pair::Response = request::<_, (), _>(
			&self.inner,
			http::Method::GET,
			&uri,
			None,
		).await?;
		Ok(res.handle)
	}

	pub async fn get_key_pair_public_parameter(
		&self,
		handle: &aziot_key_common::KeyHandle,
		parameter_name: &str,
	) -> Result<String, std::io::Error> {
		let uri = format!("/parameters/{}", percent_encoding::percent_encode(parameter_name.as_bytes(), http_common::PATH_SEGMENT_ENCODE_SET));

		let body = aziot_key_common_http::get_key_pair_public_parameter::Request {
			key_handle: handle.clone(),
		};

		let res: aziot_key_common_http::get_key_pair_public_parameter::Response = request(
			&self.inner,
			http::Method::POST,
			&uri,
			Some(&body),
		).await?;
		Ok(res.value)
	}

	pub async fn create_key_if_not_exists(
		&self,
		id: &str,
		value: aziot_key_common::CreateKeyValue,
	) -> Result<aziot_key_common::KeyHandle, std::io::Error> {
		let body = match value {
			aziot_key_common::CreateKeyValue::Generate { length } => aziot_key_common_http::create_key_if_not_exists::Request {
				id: id.to_owned(),
				generate_key_len: Some(length),
				import_key_bytes: None,
			},
			aziot_key_common::CreateKeyValue::Import { bytes } => aziot_key_common_http::create_key_if_not_exists::Request {
				id: id.to_owned(),
				generate_key_len: None,
				import_key_bytes: Some(http_common::ByteString(bytes)),
			},
		};

		let res: aziot_key_common_http::create_key_if_not_exists::Response = request(
			&self.inner,
			http::Method::POST,
			"/key",
			Some(&body),
		).await?;
		Ok(res.handle)
	}

	pub async fn sign(
		&self,
		handle: &aziot_key_common::KeyHandle,
		mechanism: aziot_key_common::SignMechanism,
		digest: &[u8],
	) -> Result<Vec<u8>, std::io::Error> {
		let body = aziot_key_common_http::sign::Request {
			key_handle: handle.clone(),
			parameters: match mechanism {
				aziot_key_common::SignMechanism::Ecdsa => aziot_key_common_http::sign::Parameters::Ecdsa {
					digest: http_common::ByteString(digest.to_owned()),
				},

				aziot_key_common::SignMechanism::RsaPkcs1 { message_digest } => aziot_key_common_http::sign::Parameters::RsaPkcs1 {
					message_digest_algorithm: match message_digest {
						aziot_key_common::RsaPkcs1MessageDigest::Sha1 => "sha1".to_owned(),
						aziot_key_common::RsaPkcs1MessageDigest::Sha224 => "sha224".to_owned(),
						aziot_key_common::RsaPkcs1MessageDigest::Sha256 => "sha256".to_owned(),
						aziot_key_common::RsaPkcs1MessageDigest::Sha384 => "sha384".to_owned(),
						aziot_key_common::RsaPkcs1MessageDigest::Sha512 => "sha512".to_owned(),
					},
					message: http_common::ByteString(digest.to_owned()),
				},

				aziot_key_common::SignMechanism::RsaPss { mask_generation_function, salt_len } =>
					unimplemented!("sign(RSA_PSS, {:?}, {})", mask_generation_function, salt_len),

				aziot_key_common::SignMechanism::HmacSha256 => aziot_key_common_http::sign::Parameters::HmacSha256 {
					message: http_common::ByteString(digest.to_owned()),
				},
			},
		};

		let res: aziot_key_common_http::sign::Response = request(
			&self.inner,
			http::Method::POST,
			"/sign",
			Some(&body),
		).await?;
		let signature = res.signature.0;
		Ok(signature)
	}

	pub async fn encrypt(
		&self,
		handle: &aziot_key_common::KeyHandle,
		mechanism: aziot_key_common::EncryptMechanism,
		plaintext: &[u8],
	) -> Result<Vec<u8>, std::io::Error> {
		let body = aziot_key_common_http::encrypt::Request {
			key_handle: handle.clone(),
			parameters: match mechanism {
				aziot_key_common::EncryptMechanism::Aead { iv, aad } => aziot_key_common_http::encrypt::Parameters::Aead {
					iv: http_common::ByteString(iv),
					aad: http_common::ByteString(aad),
				},
			},
			plaintext: http_common::ByteString(plaintext.to_owned()),
		};

		let res: aziot_key_common_http::encrypt::Response = request(
			&self.inner,
			http::Method::POST,
			"/encrypt",
			Some(&body),
		).await?;
		let ciphertext = res.ciphertext.0;
		Ok(ciphertext)
	}

	pub async fn decrypt(
		&self,
		handle: &aziot_key_common::KeyHandle,
		mechanism: aziot_key_common::EncryptMechanism,
		ciphertext: &[u8],
	) -> Result<Vec<u8>, std::io::Error> {
		let body = aziot_key_common_http::decrypt::Request {
			key_handle: handle.clone(),
			parameters: match mechanism {
				aziot_key_common::EncryptMechanism::Aead { iv, aad } => aziot_key_common_http::decrypt::Parameters::Aead {
					iv: http_common::ByteString(iv),
					aad: http_common::ByteString(aad),
				},
			},
			ciphertext: http_common::ByteString(ciphertext.to_owned()),
		};

		let res: aziot_key_common_http::decrypt::Response = request(
			&self.inner,
			http::Method::POST,
			"/decrypt",
			Some(&body),
		).await?;
		let plaintext = res.plaintext.0;
		Ok(plaintext)
	}
}

async fn request<TConnect, TRequest, TResponse>(
	client: &hyper::Client<TConnect, hyper::Body>,
	method: http::Method,
	uri: &str,
	body: Option<&TRequest>,
) -> std::io::Result<TResponse>
where
	TConnect: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
	TRequest: serde::Serialize,
	TResponse: serde::de::DeserializeOwned,
{
	let uri = format!("http://foo{}", uri);

	let req =
		hyper::Request::builder()
		.method(method)
		.uri(uri);
	let req =
		if let Some(body) = body {
			let body = serde_json::to_vec(body).expect("serializing request body to JSON cannot fail").into();
			req
				.header(hyper::header::CONTENT_TYPE, "application/json")
				.body(body)
		}
		else {
			req.body(Default::default())
		};
	let req = req.expect("cannot fail to create hyper request");

	let res = client.request(req).await.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

	let (http::response::Parts { status: res_status_code, headers, .. }, body) = res.into_parts();

	let mut is_json = false;
	for (header_name, header_value) in headers {
		if header_name == Some(hyper::header::CONTENT_TYPE) {
			let value = header_value.to_str().map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			if value == "application/json" {
				is_json = true;
			}
		}
	}

	if !is_json {
		return Err(std::io::Error::new(std::io::ErrorKind::Other, "malformed HTTP response"));
	}

	let body = hyper::body::to_bytes(body).await.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

	let res: TResponse = match res_status_code {
		hyper::StatusCode::OK => {
			let res = serde_json::from_slice(&body).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			res
		},

		res_status_code if res_status_code.is_client_error() || res_status_code.is_server_error() => {
			let res: aziot_key_common_http::Error = serde_json::from_slice(&body).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			return Err(std::io::Error::new(std::io::ErrorKind::Other, res.message));
		},

		_ => return Err(std::io::Error::new(std::io::ErrorKind::Other, "malformed HTTP response")),
	};
	Ok(res)
}
