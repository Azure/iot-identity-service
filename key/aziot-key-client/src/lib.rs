// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::let_and_return,
	clippy::missing_errors_doc,
	clippy::must_use_candidate,
	clippy::shadow_unrelated,
)]

pub struct Client {
	connector: http_common::Connector,
}

impl Client {
	pub fn new(connector: http_common::Connector) -> Self {
		Client {
			connector,
		}
	}

	pub fn create_key_pair_if_not_exists(
		&self,
		id: &str,
		preferred_algorithms: Option<&str>,
	) -> std::io::Result<aziot_key_common::KeyHandle> {
		let mut stream = self.connector.connect()?;

		let body = aziot_key_common_http::create_key_pair_if_not_exists::Request {
			id: id.to_owned(),
			preferred_algorithms: preferred_algorithms.map(ToOwned::to_owned),
		};

		let res: aziot_key_common_http::create_key_pair_if_not_exists::Response = request(
			&mut stream,
			&http::Method::POST,
			"/keypair",
			Some(&body),
		)?;
		Ok(res.handle)
	}

	pub fn load_key_pair(
		&self,
		id: &str,
	) -> std::io::Result<aziot_key_common::KeyHandle> {
		let mut stream = self.connector.connect()?;

		let uri = format!("/keypair/{}", percent_encoding::percent_encode(id.as_bytes(), http_common::PATH_SEGMENT_ENCODE_SET));

		let res: aziot_key_common_http::load::Response = request::<_, (), _>(
			&mut stream,
			&http::Method::GET,
			&uri,
			None,
		)?;
		Ok(res.handle)
	}

	pub fn get_key_pair_public_parameter(
		&self,
		handle: &aziot_key_common::KeyHandle,
		parameter_name: &str,
	) -> std::io::Result<String> {
		let mut stream = self.connector.connect()?;

		let uri = format!("/parameters/{}", percent_encoding::percent_encode(parameter_name.as_bytes(), http_common::PATH_SEGMENT_ENCODE_SET));

		let body = aziot_key_common_http::get_key_pair_public_parameter::Request {
			key_handle: handle.clone(),
		};

		let res: aziot_key_common_http::get_key_pair_public_parameter::Response = request(
			&mut stream,
			&http::Method::POST,
			&uri,
			Some(&body),
		)?;
		Ok(res.value)
	}

	pub fn create_key_if_not_exists(
		&self,
		id: &str,
		value: aziot_key_common::CreateKeyValue,
	) -> std::io::Result<aziot_key_common::KeyHandle> {
		let mut stream = self.connector.connect()?;

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
			&mut stream,
			&http::Method::POST,
			"/key",
			Some(&body),
		)?;
		Ok(res.handle)
	}

	pub fn load_key(
		&self,
		id: &str,
	) -> std::io::Result<aziot_key_common::KeyHandle> {
		let mut stream = self.connector.connect()?;

		let uri = format!("/key/{}", percent_encoding::percent_encode(id.as_bytes(), http_common::PATH_SEGMENT_ENCODE_SET));

		let res: aziot_key_common_http::load::Response = request::<_, (), _>(
			&mut stream,
			&http::Method::GET,
			&uri,
			None,
		)?;
		Ok(res.handle)
	}

	pub fn create_derived_key(
		&self,
		base_handle: &aziot_key_common::KeyHandle,
		derivation_data: &[u8],
	) -> std::io::Result<aziot_key_common::KeyHandle> {
		let mut stream = self.connector.connect()?;

		let body = aziot_key_common_http::create_derived_key::Request {
			base_handle: base_handle.clone(),
			derivation_data: http_common::ByteString(derivation_data.to_owned()),
		};

		let res: aziot_key_common_http::create_derived_key::Response = request(
			&mut stream,
			&http::Method::POST,
			"/derivedkey",
			Some(&body),
		)?;
		Ok(res.handle)
	}

	pub fn export_derived_key(
		&self,
		handle: &aziot_key_common::KeyHandle,
	) -> std::io::Result<Vec<u8>> {
		let mut stream = self.connector.connect()?;

		let body = aziot_key_common_http::export_derived_key::Request {
			handle: handle.clone(),
		};

		let res: aziot_key_common_http::export_derived_key::Response = request(
			&mut stream,
			&http::Method::POST,
			"/derivedkey/export",
			Some(&body),
		)?;
		Ok(res.key.0)
	}

	pub fn sign(
		&self,
		handle: &aziot_key_common::KeyHandle,
		mechanism: aziot_key_common::SignMechanism,
		digest: &[u8],
	) -> std::io::Result<Vec<u8>> {
		let mut stream = self.connector.connect()?;

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
			&mut stream,
			&http::Method::POST,
			"/sign",
			Some(&body),
		)?;
		let signature = res.signature.0;
		Ok(signature)
	}

	pub fn encrypt(
		&self,
		handle: &aziot_key_common::KeyHandle,
		mechanism: aziot_key_common::EncryptMechanism,
		plaintext: &[u8],
	) -> std::io::Result<Vec<u8>> {
		let mut stream = self.connector.connect()?;

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
			&mut stream,
			&http::Method::POST,
			"/encrypt",
			Some(&body),
		)?;
		let ciphertext = res.ciphertext.0;
		Ok(ciphertext)
	}

	pub fn decrypt(
		&self,
		handle: &aziot_key_common::KeyHandle,
		mechanism: aziot_key_common::EncryptMechanism,
		ciphertext: &[u8],
	) -> std::io::Result<Vec<u8>> {
		let mut stream = self.connector.connect()?;

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
			&mut stream,
			&http::Method::POST,
			"/decrypt",
			Some(&body),
		)?;
		let plaintext = res.plaintext.0;
		Ok(plaintext)
	}
}

impl std::fmt::Debug for Client {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Client").finish()
	}
}

fn request<TStream, TRequest, TResponse>(
	stream: &mut TStream,
	method: &http::Method,
	uri: &str,
	body: Option<&TRequest>,
) -> std::io::Result<TResponse>
where
	TStream: std::io::Read + std::io::Write,
	TRequest: serde::Serialize,
	TResponse: serde::de::DeserializeOwned,
{
	write!(stream, "{method} {uri} HTTP/1.1\r\n", method = method, uri = uri)?;

	if let Some(body) = body {
		let body = serde_json::to_string(body).expect("serializing request body to JSON cannot fail");
		let body_len = body.len();

		write!(stream, "\
			content-length: {body_len}\r\n\
			content-type: application/json\r\n\
			\r\n\
			{body}
			",
			body_len = body_len,
			body = body,
		)?;
	}
	else {
		stream.write_all(b"\r\n")?;
	}

	// While `connection: close` with a `stream.read_to_end(&mut buf)` ought to be sufficient, hyper sometimes fails to close the connection
	// and causes read_to_end to block indefinitely. Verified through strace that hyper sometimes completes a writev() to write to the socket but
	// never close()s it.
	//
	// So parse more robustly by only reading up to the length expected.

	let mut buf = vec![0_u8; 512];
	let mut read_so_far = 0;

	let (res_status_code, body) = loop {
		let new_read = loop {
			match stream.read(&mut buf[read_so_far..]) {
				Ok(new_read) => break new_read,
				Err(err) if err.kind() == std::io::ErrorKind::Interrupted => (),
				Err(err) => return Err(err),
			}
		};
		read_so_far += new_read;

		if let Some((res_status_code, body)) = try_parse_response(&buf[..read_so_far], new_read)? {
			break (res_status_code, body);
		}

		if read_so_far == buf.len() {
			buf.resize(buf.len() * 2, 0_u8);
		}
	};

	let res: TResponse = match res_status_code {
		Some(200) => {
			let res = serde_json::from_slice(body).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			res
		},

		Some(400..=499) | Some(500..=599) => {
			let res: aziot_key_common_http::Error = serde_json::from_slice(body).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			return Err(std::io::Error::new(std::io::ErrorKind::Other, res.message));
		},

		Some(_) | None => return Err(std::io::Error::new(std::io::ErrorKind::Other, "malformed HTTP response")),
	};
	Ok(res)
}

fn try_parse_response(buf: &[u8], new_read: usize) -> std::io::Result<Option<(Option<u16>, &[u8])>> {
	let mut headers = [httparse::EMPTY_HEADER; 16];

	let mut res = httparse::Response::new(&mut headers);

	let body_start_pos = match res.parse(&buf) {
		Ok(httparse::Status::Complete(body_start_pos)) => body_start_pos,
		Ok(httparse::Status::Partial) if new_read == 0 => return Ok(None),
		Ok(httparse::Status::Partial) => return Err(std::io::ErrorKind::UnexpectedEof.into()),
		Err(err) => return Err(std::io::Error::new(std::io::ErrorKind::Other, err)),
	};

	let res_status_code = res.code;

	let mut content_length = None;
	let mut is_json = false;
	for header in &headers {
		if header.name.eq_ignore_ascii_case("content-length") {
			let value = std::str::from_utf8(header.value).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			let value: usize = value.parse().map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			content_length = Some(value);
		}
		else if header.name.eq_ignore_ascii_case("content-type") {
			let value = std::str::from_utf8(header.value).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			if value == "application/json" {
				is_json = true;
			}
		}
	}

	if !is_json {
		return Err(std::io::Error::new(std::io::ErrorKind::Other, "malformed HTTP response"));
	}

	let body = &buf[body_start_pos..];
	let body =
		if let Some(content_length) = content_length {
			if body.len() < content_length {
				return Ok(None);
			}
			else {
				&body[..content_length]
			}
		}
		else {
			// Without a content-length, read until there's no more to read.
			if new_read == 0 {
				body
			}
			else {
				return Ok(None);
			}
		};

	Ok(Some((res_status_code, body)))
}
