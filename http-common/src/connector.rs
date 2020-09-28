// Copyright (c) Microsoft. All rights reserved.

#[derive(Clone, Debug, PartialEq)]
pub enum Connector {
	Fd { original_specifier: String, fd: std::os::unix::io::RawFd },
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
			"fd" => {
				const SD_LISTEN_FDS_START: std::os::unix::io::RawFd = 3;

				// Mimic sd_listen_fds and sd_listen_fds_with_names from libsystemd.
				//
				// Ref: https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html
				//
				// >[sd_listen_fds] parses the number passed in the $LISTEN_FDS environment variable, then sets the FD_CLOEXEC flag
				// >for the parsed number of file descriptors starting from SD_LISTEN_FDS_START. Finally, it returns the parsed number.
				//
				// >sd_listen_fds_with_names() is like sd_listen_fds(), but optionally also returns an array of strings with identification names
				// >for the passed file descriptors, if that is available and the names parameter is non-NULL. This information is read
				// >from the $LISTEN_FDNAMES variable, which may contain a colon-separated list of names.

				let listen_pid = {
					let listen_pid =
						std::env::var("LISTEN_PID")
						.map_err(|err| ConnectorError { uri: uri.clone(), inner: format!("could not read LISTEN_PID env var: {}", err).into() })?
						.parse()
						.map_err(|err| ConnectorError { uri: uri.clone(), inner: format!("could not read LISTEN_PID env var: {}", err).into() })?;
					nix::unistd::Pid::from_raw(listen_pid)
				};
				let current_pid = nix::unistd::Pid::this();
				if listen_pid != current_pid {
					// The env vars are not for us. Perhaps we're being spawned by another socket-activated service and we inherited these env vars from it.
					//
					// Either way, this is the same as if the env var wasn't set at all. That is, the caller wants us to find a socket-activated fd,
					// but we weren't started via socket activation.
					return Err(ConnectorError {
						uri: uri.clone(),
						inner: format!("LISTEN_PID env var is set to {} but current process pid is {}", listen_pid, current_pid).into(),
					});
				}

				let listen_fds: std::os::unix::io::RawFd =
					std::env::var("LISTEN_FDS")
					.map_err(|err| ConnectorError { uri: uri.clone(), inner: format!("could not read LISTEN_FDS env var: {}", err).into() })?
					.parse()
					.map_err(|err| ConnectorError { uri: uri.clone(), inner: format!("could not read LISTEN_FDS env var: {}", err).into() })?;

				// fcntl(CLOEXEC) all the fds so that they aren't inherited by the child processes.
				// Note that we want to do this for all the fds, not just the one we're looking for.
				for fd in SD_LISTEN_FDS_START..(SD_LISTEN_FDS_START + listen_fds) {
					if let Err(err) = nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC)) {
						return Err(ConnectorError {
							uri: uri.clone(),
							inner: format!("could not fcntl({}, F_SETFD, FD_CLOEXEC): {}", fd, err).into(),
						});
					}
				}

				let listen_fdnames = std::env::var("LISTEN_FDNAMES");
				let listen_fdnames =
					listen_fdnames
					.as_ref()
					.map(std::ops::Deref::deref)
					.unwrap_or_default()
					.split(':');

				let socket_num_or_name =
					uri.host_str()
					.ok_or_else(|| ConnectorError { uri: uri.clone(), inner: "fd URI does not have a host".into() })?;

				let socket_num = {
					if let Ok(socket_num) = socket_num_or_name.parse::<std::os::unix::io::RawFd>() {
						socket_num
					}
					else {
						let listen_fds: usize =
							std::convert::TryInto::try_into(listen_fds)
							.map_err(|err| ConnectorError {
								uri: uri.clone(),
								inner: format!("invalid value of LISTEN_FDS {:?}: {}", listen_fds, err).into(),
							})?;
						let expected_socket_name = socket_num_or_name;
						let socket_num =
							listen_fdnames
							.take(listen_fds)
							.enumerate()
							.find_map(|(socket_num, socket_name)| {
								if socket_name != expected_socket_name {
									return None;
								}

								let socket_num = std::convert::TryInto::try_into(socket_num).ok()?;
								Some(socket_num)
							})
							.ok_or_else(|| ConnectorError {
								uri: uri.clone(),
								inner: "fd URI is a socket name but no socket with that name was given to the process".into(),
							})?;
						socket_num
					}
				};

				// The socket number in the config file is the offset from SD_LISTEN_FDS_START, ie 3.
				//
				// In other words, fd://0 corresponds to fd 3, which is indeed the first socket given by systemd to the process.
				// Similarly, fd://foo.socket where LISTEN_FDNAMES is set to "foo.socket" corresponds to the first socket, which is again fd 3.
				let fd = socket_num + SD_LISTEN_FDS_START;
				Ok(Connector::Fd { original_specifier: socket_num_or_name.to_owned(), fd })
			},

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
			Connector::Fd { .. } => Err(std::io::Error::new(std::io::ErrorKind::Other, "connecting to fd:// URIs is not supported")),

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
			Connector::Fd { fd, .. } => {
				let sock_addr = nix::sys::socket::getsockname(fd).map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
				match sock_addr {
					nix::sys::socket::SockAddr::Inet(_) => {
						let listener = unsafe { std::os::unix::io::FromRawFd::from_raw_fd(fd) };
						let listener = tokio::net::TcpListener::from_std(listener)?;
						Ok(Incoming::Http(listener))
					},

					nix::sys::socket::SockAddr::Unix(_) => {
						let listener = unsafe { std::os::unix::io::FromRawFd::from_raw_fd(fd) };
						let listener = tokio::net::UnixListener::from_std(listener)?;
						Ok(Incoming::Unix(listener))
					},

					sock_addr => Err(std::io::Error::new(
						std::io::ErrorKind::Other,
						format!("fd:// URI points socket with unsupported address family {:?}", sock_addr.family()),
					)),
				}
			},

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
			Connector::Fd { .. } => Box::pin(futures_util::future::err(std::io::Error::new(
				std::io::ErrorKind::Other,
				"connecting to fd:// URIs is not supported",
			))),

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
			Connector::Fd { original_specifier, .. } => {
				let mut url: url::Url = "fd://foo".parse().expect("hard-coded URL parses successfully");
				url.set_host(Some(original_specifier))
					.map_err(|err| serde::ser::Error::custom(format!("could not set host {:?}: {:?}", original_specifier, err)))?;
				url
			},

			Connector::Http { host, port } => {
				let mut url: url::Url = "http://foo".parse().expect("hard-coded URL parses successfully");
				url.set_host(Some(host))
					.map_err(|err| serde::ser::Error::custom(format!("could not set host {:?}: {:?}", host, err)))?;
				if *port != 80 {
					url.set_port(Some(*port)).map_err(|()| serde::ser::Error::custom(format!("could not set port {:?}", port)))?;
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
