// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::default_trait_access,
	clippy::let_and_return,
	clippy::missing_errors_doc,
	clippy::must_use_candidate,
	clippy::similar_names,
)]

#[derive(Debug)]
pub struct Client {
	inner: hyper::Client<http_common::Connector, hyper::Body>,
}

impl Client {
	pub fn new(connector: http_common::Connector) -> Self {
		let inner = hyper::Client::builder().build(connector);
		Client {
			inner,
		}
	}

	pub async fn create_key_pair_if_not_exists(
		&self,
		id: &str,
		preferred_algorithms: Option<&str>,
	) -> std::io::Result<aziot_key_common::KeyHandle> {
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
	) -> std::io::Result<aziot_key_common::KeyHandle> {
		let uri = format!("/keypair/{}", percent_encoding::percent_encode(id.as_bytes(), http_common::PATH_SEGMENT_ENCODE_SET));

		let res: aziot_key_common_http::load::Response = request::<(), _>(
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
	) -> std::io::Result<String> {
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
	) -> std::io::Result<aziot_key_common::KeyHandle> {
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

	pub async fn load_key(
		&self,
		id: &str,
	) -> std::io::Result<aziot_key_common::KeyHandle> {
		let uri = format!("/key/{}", percent_encoding::percent_encode(id.as_bytes(), http_common::PATH_SEGMENT_ENCODE_SET));

		let res: aziot_key_common_http::load::Response = request::<(), _>(
			&self.inner,
			http::Method::GET,
			&uri,
			None,
		).await?;
		Ok(res.handle)
	}

	pub async fn create_derived_key(
		&self,
		base_handle: &aziot_key_common::KeyHandle,
		derivation_data: &[u8],
	) -> std::io::Result<aziot_key_common::KeyHandle> {
		let body = aziot_key_common_http::create_derived_key::Request {
			base_handle: base_handle.clone(),
			derivation_data: http_common::ByteString(derivation_data.to_owned()),
		};

		let res: aziot_key_common_http::create_derived_key::Response = request(
			&self.inner,
			http::Method::POST,
			"/derivedkey",
			Some(&body),
		).await?;
		Ok(res.handle)
	}

	pub async fn export_derived_key(
		&self,
		handle: &aziot_key_common::KeyHandle,
	) -> std::io::Result<Vec<u8>> {
		let body = aziot_key_common_http::export_derived_key::Request {
			handle: handle.clone(),
		};

		let res: aziot_key_common_http::export_derived_key::Response = request(
			&self.inner,
			http::Method::POST,
			"/derivedkey/export",
			Some(&body),
		).await?;
		Ok(res.key.0)
	}

	pub async fn sign(
		&self,
		handle: &aziot_key_common::KeyHandle,
		mechanism: aziot_key_common::SignMechanism,
		digest: &[u8],
	) -> std::io::Result<Vec<u8>> {
		let body = aziot_key_common_http::sign::Request {
			key_handle: handle.clone(),
			parameters: match mechanism {
				aziot_key_common::SignMechanism::Ecdsa => aziot_key_common_http::sign::Parameters::Ecdsa {
					digest: http_common::ByteString(digest.to_owned()),
				},

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
	) -> std::io::Result<Vec<u8>> {
		let body = aziot_key_common_http::encrypt::Request {
			key_handle: handle.clone(),
			parameters: match mechanism {
				aziot_key_common::EncryptMechanism::Aead { iv, aad } => aziot_key_common_http::encrypt::Parameters::Aead {
					iv: http_common::ByteString(iv),
					aad: http_common::ByteString(aad),
				},

				aziot_key_common::EncryptMechanism::RsaPkcs1 => aziot_key_common_http::encrypt::Parameters::RsaPkcs1,

				aziot_key_common::EncryptMechanism::RsaNoPadding => aziot_key_common_http::encrypt::Parameters::RsaNoPadding,
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
	) -> std::io::Result<Vec<u8>> {
		let body = aziot_key_common_http::decrypt::Request {
			key_handle: handle.clone(),
			parameters: match mechanism {
				aziot_key_common::EncryptMechanism::Aead { iv, aad } => aziot_key_common_http::encrypt::Parameters::Aead {
					iv: http_common::ByteString(iv),
					aad: http_common::ByteString(aad),
				},

				aziot_key_common::EncryptMechanism::RsaPkcs1 => aziot_key_common_http::encrypt::Parameters::RsaPkcs1,

				aziot_key_common::EncryptMechanism::RsaNoPadding => aziot_key_common_http::encrypt::Parameters::RsaNoPadding,
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

async fn request<TRequest, TResponse>(
	client: &hyper::Client<http_common::Connector, hyper::Body>,
	method: http::Method,
	uri: &str,
	body: Option<&TRequest>,
) -> std::io::Result<TResponse>
where
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
