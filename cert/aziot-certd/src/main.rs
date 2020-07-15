#![deny(rust_2018_idioms, warnings)]
#![allow(
	clippy::let_and_return,
	clippy::type_complexity,
)]

mod http;

#[tokio::main]
async fn main() -> Result<(), Error> {
	// TODO: Read this from config
	let homedir_path: std::path::PathBuf =
		std::env::var_os("HOMEDIR_PATH")
		.ok_or_else(|| aziot_certd::Error::Internal(aziot_certd::InternalError::InvalidConfig("HOMEDIR_PATH not set".to_owned())))?.into();

	let key_client = {
		struct Connector;

		impl aziot_key_client::Connector for Connector {
			fn connect(&self) -> std::io::Result<Box<dyn aziot_key_client::Stream>> {
				let stream = std::net::TcpStream::connect(("localhost", 8888))?;
				Ok(Box::new(stream))
			}
		}

		let key_client = aziot_key_client::Client::new(Box::new(Connector));
		let key_client = std::sync::Arc::new(key_client);
		key_client
	};

	let mut server = aziot_certd::Server::new(homedir_path, key_client)?;

	for (key, value) in std::env::vars() {
		if key.starts_with("PRELOADED_CERT:") {
			let key = key["PRELOADED_CERT:".len()..].to_owned();

			let value: std::path::PathBuf = value.into();

			server.preload_cert(key, value);
		}
	}

	let server = std::sync::Arc::new(futures_util::lock::Mutex::new(server));

	eprintln!("Starting server...");

	let incoming = hyper::server::conn::AddrIncoming::bind(&"0.0.0.0:8889".parse()?)?;

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
