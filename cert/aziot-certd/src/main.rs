// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	clippy::default_trait_access,
	clippy::let_and_return,
	clippy::let_unit_value,
	clippy::similar_names,
	clippy::type_complexity,
)]

mod http;

#[tokio::main]
async fn main() -> Result<(), Error> {
	let config_path: std::path::PathBuf =
		std::env::var_os("AZIOT_CERTD_CONFIG")
		.map_or_else(|| "/etc/aziot/certd/config.toml".into(), Into::into);

	let config = std::fs::read(config_path).map_err(|err| aziot_certd::Error::Internal(aziot_certd::InternalError::ReadConfig(Box::new(err))))?;
	let aziot_certd::Config {
		homedir_path,
		cert_issuance,
		preloaded_certs,
		endpoints: aziot_certd::Endpoints { aziot_certd: connector, aziot_keyd: key_connector },
	} = toml::from_slice(&config).map_err(|err| aziot_certd::Error::Internal(aziot_certd::InternalError::ReadConfig(Box::new(err))))?;

	let key_client = {
		let key_client = aziot_key_client::Client::new(key_connector);
		let key_client = std::sync::Arc::new(key_client);
		key_client
	};

	let server = aziot_certd::Server::new(homedir_path, cert_issuance, preloaded_certs, key_client)?;
	let server = std::sync::Arc::new(futures_util::lock::Mutex::new(server));

	eprintln!("Starting server...");

	let incoming = connector.incoming().await?;
	let server =
		hyper::Server::builder(incoming)
		.serve(hyper::service::make_service_fn(|_| {
			let server = http::Server { inner: server.clone() };
			futures_util::future::ok::<_, std::convert::Infallible>(server)
		}));
	let () = server.await?;

	eprintln!("Server stopped.");

	Ok(())
}

struct Error(Box<dyn std::error::Error>, backtrace::Backtrace);

impl std::fmt::Debug for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		writeln!(f, "{}", self.0)?;

		let mut source = self.0.source();
		while let Some(err) = source {
			writeln!(f, "caused by: {}", err)?;
			source = err.source();
		}

		writeln!(f, "{:?}", self.1)?;

		Ok(())
	}
}

impl<E> From<E> for Error where E: Into<Box<dyn std::error::Error>> {
	fn from(err: E) -> Self {
		Error(err.into(), Default::default())
	}
}
