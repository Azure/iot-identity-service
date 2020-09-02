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
		std::env::var_os("AZIOT_KEYD_CONFIG")
		.map_or_else(|| "/etc/aziot/keyd/config.toml".into(), Into::into);

	let config = std::fs::read(config_path).map_err(|err| aziot_keyd::Error::Internal(aziot_keyd::InternalError::ReadConfig(Box::new(err))))?;
	let aziot_keyd::Config {
		aziot_keys,
		preloaded_keys,
		endpoints: aziot_keyd::Endpoints { aziot_keyd: connector },
	} = toml::from_slice(&config).map_err(|err| aziot_keyd::Error::Internal(aziot_keyd::InternalError::ReadConfig(Box::new(err))))?;

	let server = aziot_keyd::Server::new(aziot_keys, preloaded_keys)?;
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
