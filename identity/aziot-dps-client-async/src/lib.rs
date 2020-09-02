// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::default_trait_access,
	clippy::let_and_return,
	clippy::let_unit_value,
	clippy::missing_errors_doc,
	clippy::similar_names,
	clippy::too_many_arguments,
	clippy::too_many_lines,
	clippy::type_complexity,
)]

pub mod model;

pub const DPS_ENCODE_SET: &percent_encoding::AsciiSet =
	&http_common::PATH_SEGMENT_ENCODE_SET
		.add(b'=');

pub async fn register(
	uri: &str,
	scope_id: &str,
	registration_id: &str,
	sas_key: Option<String>,
	identity_cert: Option<String>,
	identity_pk: Option<String>,
	key_client: &aziot_key_client_async::Client,
	key_engine: &mut openssl2::FunctionalEngineRef,
	cert_client: &aziot_cert_client_async::Client,
) -> Result<model::RegistrationOperationStatus, std::io::Error> {
	let resource_uri = format!(
		"/{}/registrations/{}/register?api-version=2018-11-01", scope_id, registration_id
	);
	
	let body = model::DeviceRegistration { registration_id: Some(registration_id.into()) };
	
	let res: model::RegistrationOperationStatus = request(
		uri,
		scope_id,
		registration_id,
		http::Method::PUT,
		&resource_uri,
		sas_key,
		identity_cert,
		identity_pk,
		Some(&body),
		key_client,
		key_engine,
		cert_client,
	).await?;
	
	Ok(res)
}

pub async fn get_operation_status(
	uri: &str,
	scope_id: &str,
	registration_id: &str,
	operation_id: &str,
	sas_key: Option<String>,
	identity_cert: Option<String>,
	identity_pk: Option<String>,
	key_client: &aziot_key_client_async::Client,
	key_engine: &mut openssl2::FunctionalEngineRef,
	cert_client: &aziot_cert_client_async::Client,
) -> Result<model::RegistrationOperationStatus, std::io::Error> {
	let resource_uri = format!(
		"/{}/registrations/{}/operations/{}?api-version=2018-11-01", scope_id, registration_id, operation_id
	);
	
	let res: model::RegistrationOperationStatus = request::<(),_>(
		uri,
		scope_id,
		registration_id,
		http::Method::GET,
		&resource_uri,
		sas_key,
		identity_cert,
		identity_pk,
		None,
		key_client,
		key_engine,
		cert_client,
	).await?;
	
	Ok(res)
}

#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct Error {
	pub message: std::borrow::Cow<'static, str>,
}

async fn request<TRequest, TResponse>(
	global_endpoint: &str,
	scope_id: &str,
	registration_id: &str,
	method: http::Method,
	uri: &str,
	sas_key: Option<String>,
	identity_cert: Option<String>,
	identity_pk: Option<String>,
	body: Option<&TRequest>,
	key_client: &aziot_key_client_async::Client,
	key_engine: &mut openssl2::FunctionalEngineRef,
	cert_client: &aziot_cert_client_async::Client,
) -> std::io::Result<TResponse>
where
	TRequest: serde::Serialize,
	TResponse: serde::de::DeserializeOwned,
{
	let uri = format!("https://{}{}", global_endpoint, uri);
	
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
			req.body(hyper::Body::default())
		};
	
	let mut req = req.expect("cannot fail to create hyper request");
	
	let connector =
		if let Some(key) = sas_key.clone() {
			let (connector, token) = get_sas_connector(scope_id.into(), registration_id.into(), key, key_client).await?;

			let authorization_header_value = hyper::header::HeaderValue::from_str(&token)
				.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			req.headers_mut().append(hyper::header::AUTHORIZATION, authorization_header_value);
			connector
		}
		else { 
			get_x509_connector(
				identity_cert.expect("device identity certificate not found"),
				identity_pk.expect("device private key not found"),
				key_client,
				key_engine,
				cert_client,
			).await? 
		};

	let client = hyper::Client::builder().build(connector);
	log::debug!("DPS request {:?}", req);
	
	let res = client.request(req).await.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

	let (http::response::Parts { status: res_status_code, headers, .. }, body) = res.into_parts();
	log::debug!("DPS response status {:?}", res_status_code);
	log::debug!("DPS response headers{:?}", headers);
	
	let mut is_json = false;
	for (header_name, header_value) in headers {
		if header_name == Some(hyper::header::CONTENT_TYPE) {
			let value = header_value.to_str().map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			if value.contains("application/json") {
				is_json = true;
			}
		}
	}
	
	let body = hyper::body::to_bytes(body).await.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
	log::debug!("DPS response body {:?}", body);

	let res: TResponse = match res_status_code {
		hyper::StatusCode::OK | hyper::StatusCode::ACCEPTED => {
			if !is_json {
				return Err(std::io::Error::new(std::io::ErrorKind::Other, "malformed HTTP response"));
			}
			let res = serde_json::from_slice(&body).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			res
		},

		res_status_code if res_status_code.is_client_error() || res_status_code.is_server_error() => {
			let res: crate::Error = serde_json::from_slice(&body).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			return Err(std::io::Error::new(std::io::ErrorKind::Other, res.message));
		},

		_ => return Err(std::io::Error::new(std::io::ErrorKind::Other, "malformed HTTP response")),
	};
	
	Ok(res)
}

async fn get_sas_connector(
	scope_id: String,
	registration_id: String,
	key_handle: String,
	key_client: &aziot_key_client_async::Client,
) -> Result<(hyper_openssl::HttpsConnector<hyper::client::HttpConnector>, String), std::io::Error> {
	let key_handle = key_client.load_key(&*key_handle).await?;
	
	let token = {
		let expiry = chrono::Utc::now() + chrono::Duration::from_std(std::time::Duration::from_secs(30)).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
		let expiry = expiry.timestamp().to_string();
		let audience = format!("{}/registrations/{}", scope_id, registration_id);

		let resource_uri = percent_encoding::percent_encode(audience.to_lowercase().as_bytes(), DPS_ENCODE_SET).to_string();
		let sig_data = format!("{}\n{}", &resource_uri, expiry);

		let signature = key_client.sign(&key_handle, aziot_key_common::SignMechanism::HmacSha256, sig_data.as_bytes()).await
			.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
		
		let signature = base64::encode(&signature);

		let token =
			url::form_urlencoded::Serializer::new(format!("sr={}", resource_uri))
			.append_pair("sig", &signature)
			.append_pair("se", &expiry)
			.finish();
		token
	};

	let token = format!("SharedAccessSignature {}", token);
	

	let tls_connector = hyper_openssl::HttpsConnector::new()
		.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
	Ok((tls_connector, token))
}

async fn get_x509_connector(
	identity_cert: String,
	identity_pk: String,
	key_client: &aziot_key_client_async::Client,
	key_engine: &mut openssl2::FunctionalEngineRef,
	cert_client: &aziot_cert_client_async::Client,
) -> Result<hyper_openssl::HttpsConnector<hyper::client::HttpConnector>, std::io::Error> {
	let connector = {
		let mut tls_connector = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
			.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

		let device_id_private_key = {
			let device_id_key_handle = key_client.load_key_pair(&identity_pk).await
				.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			let device_id_key_handle = std::ffi::CString::new(device_id_key_handle.0)
				.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			let device_id_private_key = key_engine.load_private_key(&device_id_key_handle)
				.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			device_id_private_key
		};
		tls_connector.set_private_key(&device_id_private_key)
			.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

		let mut device_id_certs = {
			let device_id_certs = cert_client.get_cert(&identity_cert).await
				.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
			let device_id_certs = openssl::x509::X509::stack_from_pem(&device_id_certs)
				.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?
				.into_iter();
			device_id_certs
		};
		let client_cert = device_id_certs.next()
			.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "device identity cert not found"))?;
		tls_connector.set_certificate(&client_cert)
			.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
		for cert in device_id_certs {
			tls_connector.add_extra_chain_cert(cert)
				.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
		}

		let mut http_connector = hyper::client::HttpConnector::new();
		http_connector.enforce_http(false);
		let tls_connector = hyper_openssl::HttpsConnector::with_connector(http_connector, tls_connector)
			.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
		tls_connector
	};
	Ok(connector)
}
