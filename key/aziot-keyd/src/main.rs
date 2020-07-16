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
	let mut server = aziot_keyd::Server::new()?;

	// TODO: Read these from config
	if let Some(value) = std::env::var_os("HOMEDIR_PATH") {
		let value = std::os::unix::ffi::OsStringExt::into_vec(value);
		let value = std::ffi::CString::new(value).unwrap();

		server.set_parameter(
			std::ffi::CStr::from_bytes_with_nul(b"HOMEDIR_PATH\0").unwrap(),
			&value,
		)?;
	}

	if let Ok(value) = std::env::var("PKCS11_LIB_PATH") {
		let value = std::ffi::CString::new(value).unwrap();
		server.set_parameter(
			std::ffi::CStr::from_bytes_with_nul(b"PKCS11_LIB_PATH\0").unwrap(),
			&value,
		)?;
	}

	if let Ok(value) = std::env::var("PKCS11_BASE_SLOT") {
		let value = std::ffi::CString::new(value).unwrap();
		server.set_parameter(
			std::ffi::CStr::from_bytes_with_nul(b"PKCS11_BASE_SLOT\0").unwrap(),
			&value,
		)?;
	}

	for (key, value) in std::env::vars() {
		if key.starts_with("PRELOADED_KEY:") {
			let key = std::ffi::CString::new(key).unwrap();
			let value = std::ffi::CString::new(value).unwrap();
			server.set_parameter(&key, &value)?;
		}
	}

	let server = std::sync::Arc::new(futures_util::lock::Mutex::new(server));

	eprintln!("Starting server...");

	let incoming = hyper::server::conn::AddrIncoming::bind(&"0.0.0.0:8888".parse()?)?;

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
