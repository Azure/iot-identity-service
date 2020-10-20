// Copyright (c) Microsoft. All rights reserved.

#[derive(Clone, Debug, PartialEq)]
pub enum Connector {
    Tcp {
        host: std::sync::Arc<str>,
        port: u16,
    },
    Unix {
        socket_path: std::sync::Arc<std::path::Path>,
    },
}

#[derive(Debug)]
pub enum Stream {
    Tcp(std::net::TcpStream),
    Unix(std::os::unix::net::UnixStream),
}

#[cfg(feature = "tokio02")]
#[derive(Debug)]
pub enum AsyncStream {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
}

#[cfg(feature = "tokio02")]
#[derive(Debug)]
pub enum Incoming {
    Tcp(tokio::net::TcpListener),
    Unix(tokio::net::UnixListener),
}

impl Connector {
    pub fn new(uri: &url::Url) -> Result<Self, ConnectorError> {
        match uri.scheme() {
            "http" => {
                let host = uri
                    .host_str()
                    .ok_or_else(|| ConnectorError {
                        uri: uri.clone(),
                        inner: "http URI does not have a host".into(),
                    })?
                    .into();
                let port = uri.port().unwrap_or(80);
                Ok(Connector::Tcp { host, port })
            }

            "unix" => {
                let socket_path = uri
                    .to_file_path()
                    .map_err(|()| ConnectorError {
                        uri: uri.clone(),
                        inner: "unix URI could not be converted to a file path".into(),
                    })?
                    .into();
                Ok(Connector::Unix { socket_path })
            }

            scheme => Err(ConnectorError {
                uri: uri.clone(),
                inner: format!("unrecognized scheme {:?}", scheme).into(),
            }),
        }
    }

    pub fn connect(&self) -> std::io::Result<Stream> {
        match self {
            Connector::Tcp { host, port } => {
                let inner = std::net::TcpStream::connect((&**host, *port))?;
                Ok(Stream::Tcp(inner))
            }

            Connector::Unix { socket_path } => {
                let inner = std::os::unix::net::UnixStream::connect(socket_path)?;
                Ok(Stream::Unix(inner))
            }
        }
    }

    #[cfg(feature = "tokio02")]
    pub async fn incoming(self) -> std::io::Result<Incoming> {
        let systemd_socket = get_systemd_socket()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
        if let Some(fd) = systemd_socket {
            let sock_addr = nix::sys::socket::getsockname(fd)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
            match sock_addr {
                // Only debug builds can set up HTTP servers. Release builds must use unix sockets.
                nix::sys::socket::SockAddr::Inet(_) if cfg!(debug_assertions) => {
                    let listener = unsafe { std::os::unix::io::FromRawFd::from_raw_fd(fd) };
                    let listener = tokio::net::TcpListener::from_std(listener)?;
                    Ok(Incoming::Tcp(listener))
                }

                nix::sys::socket::SockAddr::Unix(_) => {
                    let listener = unsafe { std::os::unix::io::FromRawFd::from_raw_fd(fd) };
                    let listener = tokio::net::UnixListener::from_std(listener)?;
                    Ok(Incoming::Unix(listener))
                }

                sock_addr => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!(
                        "systemd socket has unsupported address family {:?}",
                        sock_addr.family()
                    ),
                )),
            }
        } else {
            match self {
                Connector::Tcp { host, port } =>
                // Only debug builds can set up HTTP servers. Release builds must use unix sockets.
                {
                    if cfg!(debug_assertions) {
                        let listener = tokio::net::TcpListener::bind((&*host, port)).await?;
                        Ok(Incoming::Tcp(listener))
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "servers can only use `unix://` connectors, not `http://` connectors",
                        ))
                    }
                }

                Connector::Unix { socket_path } => {
                    match std::fs::remove_file(&*socket_path) {
                        Ok(()) => (),
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                        Err(err) => return Err(err),
                    }

                    let listener = tokio::net::UnixListener::bind(socket_path)?;
                    Ok(Incoming::Unix(listener))
                }
            }
        }
    }
}

impl std::fmt::Display for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = match self {
            Connector::Tcp { host, port } => {
                let mut url: url::Url = "http://foo"
                    .parse()
                    .expect("hard-coded URL parses successfully");
                url.set_host(Some(host)).map_err(|err| {
                    serde::ser::Error::custom(format!("could not set host {:?}: {:?}", host, err))
                })?;
                if *port != 80 {
                    url.set_port(Some(*port)).map_err(|()| {
                        serde::ser::Error::custom(format!("could not set port {:?}", port))
                    })?;
                }
                url
            }

            Connector::Unix { socket_path } => {
                let socket_path = socket_path.to_str().ok_or_else(|| {
                    serde::ser::Error::custom(format!(
                        "socket path {} cannot be serialized as a utf-8 string",
                        socket_path.display()
                    ))
                })?;

                let mut url: url::Url = "unix:///foo"
                    .parse()
                    .expect("hard-coded URL parses successfully");
                url.set_path(socket_path);
                url
            }
        };
        url.fmt(f)
    }
}

impl std::str::FromStr for Connector {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri = s.parse::<url::Url>().map_err(|err| err.to_string())?;
        let connector = Connector::new(&uri).map_err(|err| err.to_string())?;
        Ok(connector)
    }
}

#[cfg(feature = "tokio02")]
impl hyper::server::accept::Accept for Incoming {
    type Conn = AsyncStream;
    type Error = std::io::Error;

    fn poll_accept(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Self::Conn, Self::Error>>> {
        loop {
            let stream = match &mut *self {
                Incoming::Tcp(listener) => match listener.poll_accept(cx) {
                    std::task::Poll::Ready(Ok((stream, _))) => Ok(AsyncStream::Tcp(stream)),
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
                }
            };

            match stream {
                Ok(stream) => return std::task::Poll::Ready(Some(Ok(stream))),
                Err(err) => match err.kind() {
                    // Client errors
                    std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset => (),

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
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _req: hyper::Uri) -> Self::Future {
        match self {
            Connector::Tcp { host, port } => {
                let (host, port) = (host.clone(), *port);
                let f = async move {
                    let inner = tokio::net::TcpStream::connect((&*host, port)).await?;
                    Ok(AsyncStream::Tcp(inner))
                };
                Box::pin(f)
            }

            Connector::Unix { socket_path } => {
                let socket_path = socket_path.clone();
                let f = async move {
                    let inner = tokio::net::UnixStream::connect(&*socket_path).await?;
                    Ok(AsyncStream::Unix(inner))
                };
                Box::pin(f)
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for Connector {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Connector;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an endpoint URI")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                s.parse().map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl serde::Serialize for Connector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let s = self.to_string();
        s.serialize(serializer)
    }
}

impl std::io::Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(inner) => inner.read(buf),
            Stream::Unix(inner) => inner.read(buf),
        }
    }

    fn read_vectored(&mut self, bufs: &mut [std::io::IoSliceMut<'_>]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(inner) => inner.read_vectored(bufs),
            Stream::Unix(inner) => inner.read_vectored(bufs),
        }
    }
}

impl std::io::Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(inner) => inner.write(buf),
            Stream::Unix(inner) => inner.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Tcp(inner) => inner.flush(),
            Stream::Unix(inner) => inner.flush(),
        }
    }

    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(inner) => inner.write_vectored(bufs),
            Stream::Unix(inner) => inner.write_vectored(bufs),
        }
    }
}

#[cfg(feature = "tokio02")]
impl tokio::io::AsyncRead for AsyncStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            AsyncStream::Tcp(inner) => std::pin::Pin::new(inner).poll_read(cx, buf),
            AsyncStream::Unix(inner) => std::pin::Pin::new(inner).poll_read(cx, buf),
        }
    }

    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [std::mem::MaybeUninit<u8>]) -> bool {
        match self {
            AsyncStream::Tcp(inner) => inner.prepare_uninitialized_buffer(buf),
            AsyncStream::Unix(inner) => inner.prepare_uninitialized_buffer(buf),
        }
    }
}

#[cfg(feature = "tokio02")]
impl tokio::io::AsyncWrite for AsyncStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            AsyncStream::Tcp(inner) => std::pin::Pin::new(inner).poll_write(cx, buf),
            AsyncStream::Unix(inner) => std::pin::Pin::new(inner).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            AsyncStream::Tcp(inner) => std::pin::Pin::new(inner).poll_flush(cx),
            AsyncStream::Unix(inner) => std::pin::Pin::new(inner).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            AsyncStream::Tcp(inner) => std::pin::Pin::new(inner).poll_shutdown(cx),
            AsyncStream::Unix(inner) => std::pin::Pin::new(inner).poll_shutdown(cx),
        }
    }
}

#[cfg(feature = "tokio02")]
impl hyper::client::connect::Connection for AsyncStream {
    fn connected(&self) -> hyper::client::connect::Connected {
        match self {
            AsyncStream::Tcp(inner) => inner.connected(),
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

/// Finds the systemd socket if one has been used to socket-activate this process.
///
/// This mimics `sd_listen_fds` from libsystemd, then returns the very first fd.
fn get_systemd_socket() -> Result<Option<std::os::unix::io::RawFd>, String> {
    // Ref: <https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html>
    //
    // >sd_listen_fds parses the number passed in the $LISTEN_FDS environment variable, then sets the FD_CLOEXEC flag
    // >for the parsed number of file descriptors starting from SD_LISTEN_FDS_START. Finally, it returns the parsed number.
    //
    // Note that this function always returns the first fd. It cannot be used for processes which expect more than one socket.
    // CS/IS/KS only expect one socket, so this is fine, but it is not the case for iotedged (mgmt and workload sockets) for example.
    //
    // If obtaining more than one fd is required in the future, keep in mind that it requires getting fds by name (by inspecting the LISTEN_FDNAMES env var)
    // instead of by number, since systemd does not pass down multiple fds in a deterministic order. The complication with LISTEN_FDNAMES is that
    // CentOS 7's systemd is too old and doesn't support it, which would mean CS/IS/KS would have to stop using systemd socket activation on CentOS 7
    // (just like iotedged). This creates more complications, because now the sockets either have to be placed in /var/lib/aziot (just like iotedged does)
    // which means host modules need to try both /run/aziot and /var/lib/aziot to connect to a service, or the services continue to bind sockets under /run/aziot
    // but have to create /run/aziot themselves on startup with ACLs for all three users and all three groups.

    const SD_LISTEN_FDS_START: std::os::unix::io::RawFd = 3;

    let listen_pid = {
        let listen_pid = match std::env::var("LISTEN_PID") {
            Ok(listen_pid) => listen_pid,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(err @ std::env::VarError::NotUnicode(_)) => {
                return Err(format!("could not read LISTEN_PID env var: {}", err))
            }
        };
        let listen_pid = listen_pid
            .parse()
            .map_err(|err| format!("could not read LISTEN_PID env var: {}", err))?;
        nix::unistd::Pid::from_raw(listen_pid)
    };
    let current_pid = nix::unistd::Pid::this();
    if listen_pid != current_pid {
        // The env vars are not for us. Perhaps we're being spawned by another socket-activated service and we inherited these env vars from it.
        //
        // Either way, this is the same as if the env var wasn't set at all. That is, the caller wants us to find a socket-activated fd,
        // but we weren't started via socket activation.
        return Ok(None);
    }

    // At this point, we expect that the remaining env vars are set and contain the socket we're looking for, else we error.
    // That is, falling back is no longer an option, so we won't return `Ok(None)`

    let listen_fds = {
        let listen_fds = match std::env::var("LISTEN_FDS") {
            Ok(listen_fds) => listen_fds,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(err @ std::env::VarError::NotUnicode(_)) => {
                return Err(format!("could not read LISTEN_FDS env var: {}", err))
            }
        };
        let listen_fds: std::os::unix::io::RawFd = listen_fds
            .parse()
            .map_err(|err| format!("could not read LISTEN_FDS env var: {}", err))?;
        listen_fds
    };
    if listen_fds == 0 {
        return Ok(None);
    }

    // fcntl(CLOEXEC) all the fds so that they aren't inherited by the child processes.
    // Note that we want to do this for all the fds, not just the one we're looking for.
    for fd in SD_LISTEN_FDS_START..(SD_LISTEN_FDS_START + listen_fds) {
        if let Err(err) = nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        ) {
            return Err(format!(
                "could not fcntl({}, F_SETFD, FD_CLOEXEC): {}",
                fd, err
            ));
        }
    }

    #[allow(clippy::identity_op)]
    // Explicitly indicating that we're returning the first fd, ie start + 0
    let fd = SD_LISTEN_FDS_START + 0;
    Ok(Some(fd))
}

#[cfg(test)]
mod tests {
    #[test]
    fn create_connector() {
        for (input, expected) in &[
            (
                "http://127.0.0.1",
                super::Connector::Tcp {
                    host: "127.0.0.1".into(),
                    port: 80,
                },
            ),
            (
                "http://127.0.0.1:8888",
                super::Connector::Tcp {
                    host: "127.0.0.1".into(),
                    port: 8888,
                },
            ),
            (
                "http://[::1]",
                super::Connector::Tcp {
                    host: "[::1]".into(),
                    port: 80,
                },
            ),
            (
                "http://[::1]:8888",
                super::Connector::Tcp {
                    host: "[::1]".into(),
                    port: 8888,
                },
            ),
            (
                "http://localhost",
                super::Connector::Tcp {
                    host: "localhost".into(),
                    port: 80,
                },
            ),
            (
                "http://localhost:8888",
                super::Connector::Tcp {
                    host: "localhost".into(),
                    port: 8888,
                },
            ),
            (
                "unix:///run/aziot/keyd.sock",
                super::Connector::Unix {
                    socket_path: std::path::Path::new("/run/aziot/keyd.sock").into(),
                },
            ),
        ] {
            let actual: super::Connector = input.parse().unwrap();
            assert_eq!(*expected, actual);

            let serialized_input = {
                let input: url::Url = input.parse().unwrap();
                serde_json::to_string(&input).unwrap()
            };
            let serialized_connector = serde_json::to_string(&actual).unwrap();
            assert_eq!(serialized_input, serialized_connector);

            let deserialized_connector: super::Connector =
                serde_json::from_str(&serialized_connector).unwrap();
            assert_eq!(*expected, deserialized_connector);
        }

        for input in &[
            // unsupported scheme
            "ftp://127.0.0.1",
        ] {
            let input = input.parse().unwrap();
            let _ = super::Connector::new(&input).unwrap_err();
        }
    }
}
