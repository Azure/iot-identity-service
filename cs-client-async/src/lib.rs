#![deny(rust_2018_idioms, warnings)]
#![allow(
	clippy::let_and_return,
	clippy::unnested_or_patterns, // TODO: Remove when https://github.com/rust-lang/rust-clippy/issues/5704 is fixed
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
	pub async fn create_cert(
		&self,
		id: &str,
		csr: &[u8],
		issuer: Option<(&str, &ks_common::KeyHandle)>,
	) -> Result<Vec<u8>, std::io::Error> {
		let body = cs_common_http::create_cert::Request {
			cert_id: id.to_owned(),
			csr: cs_common_http::Pem(csr.to_owned()),
			issuer: issuer.map(|(cert_id, private_key_handle)| cs_common_http::create_cert::Issuer {
				cert_id: cert_id.to_owned(),
				private_key_handle: private_key_handle.clone(),
			}),
		};

		let res: cs_common_http::get_cert::Response = request(
			&self.inner,
			http::Method::POST,
			"/certificates",
			Some(&body),
		).await?;
		Ok(res.pem.0)
	}

	pub async fn import_cert(
		&self,
		id: &str,
		pem: &[u8],
	) -> Result<Vec<u8>, std::io::Error> {
		let uri = format!("/certificates/{}", percent_encoding::percent_encode(id.as_bytes(), http_common::PATH_SEGMENT_ENCODE_SET));

		let body = cs_common_http::import_cert::Request {
			pem: cs_common_http::Pem(pem.to_owned()),
		};

		let res: cs_common_http::import_cert::Response = request(
			&self.inner,
			http::Method::PUT,
			&uri,
			Some(&body),
		).await?;
		Ok(res.pem.0)
	}

	pub async fn get_cert(
		&self,
		id: &str,
	) -> Result<Vec<u8>, std::io::Error> {
		let uri = format!("/certificates/{}", percent_encoding::percent_encode(id.as_bytes(), http_common::PATH_SEGMENT_ENCODE_SET));

		let res: cs_common_http::get_cert::Response = request::<_, (), _>(
			&self.inner,
			http::Method::GET,
			&uri,
			None,
		).await?;
		Ok(res.pem.0)
	}

	pub async fn delete_cert(
		&self,
		id: &str,
	) -> Result<(), std::io::Error> {
		let uri = format!("/certificates/{}", percent_encoding::percent_encode(id.as_bytes(), http_common::PATH_SEGMENT_ENCODE_SET));

		let () = request_no_content::<_, ()>(
			&self.inner,
			http::Method::DELETE,
			&uri,
			None,
		).await?;
		Ok(())
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
		hyper::StatusCode::OK | hyper::StatusCode::CREATED => {
			let res = serde_json::from_slice(&body).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			res
		},

		res_status_code if res_status_code.is_client_error() || res_status_code.is_server_error() => {
			let res: cs_common_http::Error = serde_json::from_slice(&body).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			return Err(std::io::Error::new(std::io::ErrorKind::Other, res.message));
		},

		_ => return Err(std::io::Error::new(std::io::ErrorKind::Other, "malformed HTTP response")),
	};
	Ok(res)
}

async fn request_no_content<TConnect, TRequest>(
	client: &hyper::Client<TConnect, hyper::Body>,
	method: http::Method,
	uri: &str,
	body: Option<&TRequest>,
) -> std::io::Result<()>
where
	TConnect: hyper::client::connect::Connect + Clone + Send + Sync + 'static,
	TRequest: serde::Serialize,
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

	let body = hyper::body::to_bytes(body).await.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

	match res_status_code {
		hyper::StatusCode::NO_CONTENT => Ok(()),

		res_status_code if res_status_code.is_client_error() || res_status_code.is_server_error() => {
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

			let res: cs_common_http::Error = serde_json::from_slice(&body).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			Err(std::io::Error::new(std::io::ErrorKind::Other, res.message))
		},

		_ => Err(std::io::Error::new(std::io::ErrorKind::Other, "malformed HTTP response")),
	}
}
