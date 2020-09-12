// Copyright (c) Microsoft. All rights reserved.

#[derive(Clone, Debug, PartialEq)]
pub enum Connector {
	Http { host: std::sync::Arc<str>, port: u16 },
	Unix { socket_path: std::sync::Arc<std::path::Path> },
}

#[derive(Debug)]
pub enum Stream {
	Http(std::net::TcpStream),
	Unix(std::os::unix::net::UnixStream),
}

#[cfg(feature = "tokio02")]
#[derive(Debug)]
pub enum AsyncStream {
	Http(tokio::net::TcpStream),
	Unix(tokio::net::UnixStream),
}

#[cfg(feature = "tokio02")]
#[derive(Debug)]
pub enum Incoming {
	Http(tokio::net::TcpListener),
	Unix(tokio::net::UnixListener),
}

impl Connector {
	pub fn new(uri: &url::Url) -> Result<Self, ConnectorError> {
		match uri.scheme() {
			"http" => {
				let host =
					uri.host_str()
					.ok_or_else(|| ConnectorError { uri: uri.clone(), inner: "http URI does not have a host".into() })?
					.into();
				let port = uri.port().unwrap_or(80);
				Ok(Connector::Http { host, port })
			},

			"unix" => {
				let socket_path =
					uri.to_file_path()
					.map_err(|()| ConnectorError { uri: uri.clone(), inner: "unix URI could not be converted to a file path".into() })?
					.into();
				Ok(Connector::Unix { socket_path })
			},

			scheme => Err(ConnectorError { uri: uri.clone(), inner: format!("unrecognized scheme {:?}", scheme).into() }),
		}
	}

	pub fn connect(&self) -> std::io::Result<Stream> {
		match self {
			Connector::Http { host, port } => {
				let inner = std::net::TcpStream::connect((&**host, *port))?;
				Ok(Stream::Http(inner))
			},

			Connector::Unix { socket_path } => {
				let inner = std::os::unix::net::UnixStream::connect(socket_path)?;
				Ok(Stream::Unix(inner))
			},
		}
	}

	#[cfg(feature = "tokio02")]
	pub async fn incoming(self) -> std::io::Result<Incoming> {
		match self {
			Connector::Http { host, port } => {
				let listener = tokio::net::TcpListener::bind((&*host, port)).await?;
				Ok(Incoming::Http(listener))
			},

			Connector::Unix { socket_path } => {
				match std::fs::remove_file(&*socket_path) {
					Ok(()) => (),
					Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
					Err(err) => return Err(err),
				}

				let listener = tokio::net::UnixListener::bind(socket_path)?;
				Ok(Incoming::Unix(listener))
			},
		}
	}
}

#[cfg(feature = "tokio02")]
impl hyper::server::accept::Accept for Incoming {
	type Conn = AsyncStream;
	type Error = std::io::Error;

	fn poll_accept(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Result<Self::Conn, Self::Error>>> {
		loop {
			let stream = match &mut *self {
				Incoming::Http(listener) => match listener.poll_accept(cx) {
					std::task::Poll::Ready(Ok((stream, _))) => Ok(AsyncStream::Http(stream)),
					std::task::Poll::Ready(Err(err)) => Err(err),
					std::task::Poll::Pending => return std::task::Poll::Pending,
				},

				Incoming::Unix(listener) => {
					// tokio::net::UnixListener does not have pub poll_accept.
					//
					// However the tokio::net::unix::Incoming returned from its .incoming() does.
					// Keeping an Incoming across polls is hard because it borrows a &mut of the UnixListener.
					// But it's fine to throw it away when it's Pending and make a new one for every poll, because it doesn't contain any state
					// nor has side effects from being dropped.
					let mut incoming = listener.incoming();
					match std::pin::Pin::new(&mut incoming).poll_accept(cx) {
						std::task::Poll::Ready(Ok(stream)) => Ok(AsyncStream::Unix(stream)),
						std::task::Poll::Ready(Err(err)) => Err(err),
						std::task::Poll::Pending => return std::task::Poll::Pending,
					}
				},
			};

			match stream {
				Ok(stream) => return std::task::Poll::Ready(Some(Ok(stream))),
				Err(err) => match err.kind() {
					// Client errors
					std::io::ErrorKind::ConnectionAborted |
					std::io::ErrorKind::ConnectionRefused |
					std::io::ErrorKind::ConnectionReset => (),

					_ => return std::task::Poll::Ready(Some(Err(err))),
				},
			}
		}
	}
}

#[cfg(feature = "tokio02")]
impl hyper::service::Service<hyper::Uri> for Connector {
	type Response = AsyncStream;
	type Error = std::io::Error;
	type Future = std::pin::Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
		std::task::Poll::Ready(Ok(()))
	}

	fn call(&mut self, _req: hyper::Uri) -> Self::Future {
		match self {
			Connector::Http { host, port } => {
				let (host, port) = (host.clone(), *port);
				let f = async move {
					let inner = tokio::net::TcpStream::connect((&*host, port)).await?;
					Ok(AsyncStream::Http(inner))
				};
				Box::pin(f)
			},

			Connector::Unix { socket_path } => {
				let socket_path = socket_path.clone();
				let f = async move {
					let inner = tokio::net::UnixStream::connect(&*socket_path).await?;
					Ok(AsyncStream::Unix(inner))
				};
				Box::pin(f)
			},
		}
	}
}

impl<'de> serde::Deserialize<'de> for Connector {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: serde::de::Deserializer<'de> {
		struct Visitor;

		impl<'de> serde::de::Visitor<'de> for Visitor {
			type Value = Connector;

			fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
				formatter.write_str("an endpoint URI")
			}

			fn visit_str<E>(self, s: &str) -> Result<Self::Value, E> where E: serde::de::Error {
				let uri: url::Url = s.parse().map_err(serde::de::Error::custom)?;
				let connector = Connector::new(&uri).map_err(serde::de::Error::custom)?;
				Ok(connector)
			}
		}

		deserializer.deserialize_str(Visitor)
	}
}

impl serde::Serialize for Connector {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: serde::ser::Serializer {
		let url = match self {
			Connector::Http { host, port } => {
				let mut url: url::Url = "http://foo".parse().expect("hard-coded URL parses successfully");
				url.set_host(Some(host)).map_err(|err| serde::ser::Error::custom(format!("could not serialize host {:?}: {:?}", host, err)))?;
				if *port != 80 {
					url.set_port(Some(*port)).map_err(|()| serde::ser::Error::custom(format!("could not serialize port {:?}", port)))?;
				}
				url
			},

			Connector::Unix { socket_path } => {
				let socket_path =
					socket_path.to_str()
					.ok_or_else(|| serde::ser::Error::custom(format!("socket path {} cannot be serialized as a utf-8 string", socket_path.display())))?;

				let mut url: url::Url = "unix:///foo".parse().expect("hard-coded URL parses successfully");
				url.set_path(socket_path);
				url
			},
		};
		url.serialize(serializer)
	}
}

impl std::io::Read for Stream {
	fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
		match self {
			Stream::Http(inner) => inner.read(buf),
			Stream::Unix(inner) => inner.read(buf),
		}
	}

	fn read_vectored(&mut self, bufs: &mut [std::io::IoSliceMut<'_>]) -> std::io::Result<usize> {
		match self {
			Stream::Http(inner) => inner.read_vectored(bufs),
			Stream::Unix(inner) => inner.read_vectored(bufs),
		}
	}
}

impl std::io::Write for Stream {
	fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
		match self {
			Stream::Http(inner) => inner.write(buf),
			Stream::Unix(inner) => inner.write(buf),
		}
	}

	fn flush(&mut self) -> std::io::Result<()> {
		match self {
			Stream::Http(inner) => inner.flush(),
			Stream::Unix(inner) => inner.flush(),
		}
	}

	fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
		match self {
			Stream::Http(inner) => inner.write_vectored(bufs),
			Stream::Unix(inner) => inner.write_vectored(bufs),
		}
	}
}

#[cfg(feature = "tokio02")]
impl tokio::io::AsyncRead for AsyncStream {
	fn poll_read(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut [u8]) -> std::task::Poll<std::io::Result<usize>> {
		match &mut *self {
			AsyncStream::Http(inner) => std::pin::Pin::new(inner).poll_read(cx, buf),
			AsyncStream::Unix(inner) => std::pin::Pin::new(inner).poll_read(cx, buf),
		}
	}

	unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [std::mem::MaybeUninit<u8>]) -> bool {
		match self {
			AsyncStream::Http(inner) => inner.prepare_uninitialized_buffer(buf),
			AsyncStream::Unix(inner) => inner.prepare_uninitialized_buffer(buf),
		}
	}
}

#[cfg(feature = "tokio02")]
impl tokio::io::AsyncWrite for AsyncStream {
	fn poll_write(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> std::task::Poll<std::io::Result<usize>> {
		match &mut *self {
			AsyncStream::Http(inner) => std::pin::Pin::new(inner).poll_write(cx, buf),
			AsyncStream::Unix(inner) => std::pin::Pin::new(inner).poll_write(cx, buf),
		}
	}

	fn poll_flush(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
		match &mut *self {
			AsyncStream::Http(inner) => std::pin::Pin::new(inner).poll_flush(cx),
			AsyncStream::Unix(inner) => std::pin::Pin::new(inner).poll_flush(cx),
		}
	}

	fn poll_shutdown(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<std::io::Result<()>> {
		match &mut *self {
			AsyncStream::Http(inner) => std::pin::Pin::new(inner).poll_shutdown(cx),
			AsyncStream::Unix(inner) => std::pin::Pin::new(inner).poll_shutdown(cx),
		}
	}
}

#[cfg(feature = "tokio02")]
impl hyper::client::connect::Connection for AsyncStream {
	fn connected(&self) -> hyper::client::connect::Connected {
		match self {
			AsyncStream::Http(inner) => inner.connected(),
			AsyncStream::Unix(_) => hyper::client::connect::Connected::new(),
		}
	}
}

#[derive(Debug)]
pub struct ConnectorError {
	uri: url::Url,
	inner: Box<dyn std::error::Error>,
}

impl std::fmt::Display for ConnectorError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "malformed URI {:?}", self.uri)
	}
}

impl std::error::Error for ConnectorError {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		Some(&*self.inner)
	}
}

#[cfg(test)]
mod tests {
	#[test]
	fn create_connector() {
		for (input, expected) in &[
			("http://127.0.0.1", super::Connector::Http { host: "127.0.0.1".into(), port: 80 }),
			("http://127.0.0.1:8888", super::Connector::Http { host: "127.0.0.1".into(), port: 8888 }),
			("http://[::1]", super::Connector::Http { host: "[::1]".into(), port: 80 }),
			("http://[::1]:8888", super::Connector::Http { host: "[::1]".into(), port: 8888 }),
			("http://localhost", super::Connector::Http { host: "localhost".into(), port: 80 }),
			("http://localhost:8888", super::Connector::Http { host: "localhost".into(), port: 8888 }),

			("unix:///var/run/aziot/keyd.sock", super::Connector::Unix { socket_path: std::path::Path::new("/var/run/aziot/keyd.sock").into() }),
		] {
			let input = input.parse().unwrap();
			let actual = super::Connector::new(&input).unwrap();
			assert_eq!(*expected, actual);

			let serialized_input = serde_json::to_string(&input).unwrap();
			let serialized_connector = serde_json::to_string(&actual).unwrap();
			assert_eq!(serialized_input, serialized_connector);

			let deserialized_connector: super::Connector = serde_json::from_str(&serialized_connector).unwrap();
			assert_eq!(*expected, deserialized_connector);
		}

		for input in &[
			"ftp://127.0.0.1",
		] {
			let input = input.parse().unwrap();
			let _ = super::Connector::new(&input).unwrap_err();
		}
	}
}
