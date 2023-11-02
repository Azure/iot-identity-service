// Copyright (c) Microsoft. All rights reserved.

use std::sync::atomic;

use futures_util::future;
use nix::sys::socket::{AddressFamily, SockaddrLike, SockaddrStorage};

pub const SOCKET_DEFAULT_PERMISSION: u32 = 0o660;

const SD_LISTEN_FDS_START: std::os::unix::io::RawFd = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Connector {
    Tcp {
        host: std::sync::Arc<str>,
        port: u16,
    },
    Unix {
        socket_path: std::sync::Arc<std::path::Path>,
    },
    Fd {
        fd: std::os::unix::io::RawFd,
    },
}

#[derive(Debug)]
pub enum Stream {
    Tcp(std::net::TcpStream),
    Unix(std::os::unix::net::UnixStream),
}

#[derive(Debug)]
pub enum AsyncStream {
    Tcp(tokio::net::TcpStream),
    Unix(tokio::net::UnixStream),
}

#[derive(Debug)]
pub enum Incoming {
    Tcp {
        listener: tokio::net::TcpListener,
    },
    Unix {
        listener: tokio::net::UnixListener,
        max_requests: usize,
        user_state: std::collections::BTreeMap<libc::uid_t, std::sync::Arc<atomic::AtomicUsize>>,
    },
}

impl Incoming {
    pub async fn serve<H>(
        &mut self,
        server: H,
        shutdown: tokio::sync::oneshot::Receiver<()>,
    ) -> std::io::Result<()>
    where
        H: hyper::service::Service<
                hyper::Request<hyper::Body>,
                Response = hyper::Response<hyper::Body>,
                Error = std::convert::Infallible,
            > + Clone
            + Send
            + 'static,
        <H as hyper::service::Service<hyper::Request<hyper::Body>>>::Future: Send,
    {
        // Keep track of the number of running tasks.
        let tasks = atomic::AtomicUsize::new(0);
        let tasks = std::sync::Arc::new(tasks);

        let shutdown_loop = shutdown;
        futures_util::pin_mut!(shutdown_loop);

        match self {
            Incoming::Tcp { listener } => loop {
                let accept = listener.accept();
                futures_util::pin_mut!(accept);

                match future::select(shutdown_loop, accept).await {
                    future::Either::Left((_, _)) => break,
                    future::Either::Right((tcp_stream, shutdown)) => {
                        let tcp_stream = tcp_stream?.0;

                        let server = crate::uid::UidService::new(None, 0, server.clone());

                        tasks.fetch_add(1, atomic::Ordering::AcqRel);
                        let server_tasks = tasks.clone();
                        tokio::spawn(async move {
                            if let Err(http_err) = hyper::server::conn::Http::new()
                                .serve_connection(tcp_stream, server)
                                .await
                            {
                                log::info!("Error while serving HTTP connection: {}", http_err);
                            }

                            server_tasks.fetch_sub(1, atomic::Ordering::AcqRel);
                        });

                        shutdown_loop = shutdown;
                    }
                }
            },

            Incoming::Unix {
                listener,
                max_requests,
                user_state,
            } => loop {
                let accept = listener.accept();
                futures_util::pin_mut!(accept);

                // Await either the next established connection or the shutdown signal.
                match future::select(shutdown_loop, accept).await {
                    future::Either::Left((_, _)) => break,
                    future::Either::Right((unix_stream, shutdown)) => {
                        let unix_stream = unix_stream?.0;

                        let ucred = unix_stream.peer_cred()?;
                        let servers_available = user_state
                            .entry(ucred.uid())
                            .or_insert_with(|| {
                                std::sync::Arc::new(atomic::AtomicUsize::new(*max_requests))
                            })
                            .clone();

                        let server =
                            crate::uid::UidService::new(ucred.pid(), ucred.uid(), server.clone());
                        tasks.fetch_add(1, atomic::Ordering::AcqRel);
                        let server_tasks = tasks.clone();
                        tokio::spawn(async move {
                            let available = servers_available
                                .fetch_update(
                                    atomic::Ordering::AcqRel,
                                    atomic::Ordering::Acquire,
                                    |current| current.checked_sub(1),
                                )
                                .is_ok();

                            if available {
                                if let Err(http_err) = hyper::server::conn::Http::new()
                                    .serve_connection(unix_stream, server)
                                    .await
                                {
                                    log::info!("Error while serving HTTP connection: {}", http_err);
                                }

                                servers_available.fetch_add(1, atomic::Ordering::AcqRel);
                            } else {
                                log::info!(
                                    "Max simultaneous connections reached for user {}",
                                    ucred.uid()
                                );
                            }

                            server_tasks.fetch_sub(1, atomic::Ordering::AcqRel);
                        });

                        shutdown_loop = shutdown;
                    }
                };
            },
        }

        // Wait for all running server tasks to finish before returning.
        let poll_ms = std::time::Duration::from_millis(100);

        while tasks.load(atomic::Ordering::Acquire) != 0 {
            tokio::time::sleep(poll_ms).await;
        }

        Ok(())
    }

    pub fn default_max_requests() -> usize {
        10
    }

    pub fn is_default_max_requests(max_requests: &usize) -> bool {
        *max_requests == Incoming::default_max_requests()
    }
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

            "fd" => {
                let host = uri.host_str().ok_or_else(|| ConnectorError {
                    uri: uri.clone(),
                    inner: "fd URI does not have a host".into(),
                })?;

                // Try to parse the host as an fd number.
                let fd = match host.parse::<std::os::unix::io::RawFd>() {
                    Ok(fd) => {
                        // Host is an fd number.
                        fd
                    }
                    Err(_) => {
                        // Host is not an fd number. Parse it as an fd name.
                        socket_name_to_fd(host).map_err(|message| ConnectorError {
                            uri: uri.clone(),
                            inner: message.into(),
                        })?
                    }
                };

                Ok(Connector::Fd { fd })
            }

            scheme => Err(ConnectorError {
                uri: uri.clone(),
                inner: format!("unrecognized scheme {scheme:?}").into(),
            }),
        }
    }

    pub fn into_client<B>(self) -> hyper::Client<Connector, B>
    where
        B: hyper::body::HttpBody + Send,
        B::Data: Send,
    {
        match self {
            Connector::Tcp { .. } | Connector::Fd { .. } => hyper::Client::builder().build(self),
            // we don't need connection pool'ing for unix sockets.
            Connector::Unix { .. } => hyper::Client::builder()
                .pool_max_idle_per_host(0)
                .build(self),
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

            Connector::Fd { fd } => {
                let inner = if is_unix_fd(*fd)? {
                    let inner: std::os::unix::net::UnixStream =
                        unsafe { std::os::unix::io::FromRawFd::from_raw_fd(*fd) };

                    Stream::Unix(inner)
                } else {
                    let inner: std::net::TcpStream =
                        unsafe { std::os::unix::io::FromRawFd::from_raw_fd(*fd) };

                    Stream::Tcp(inner)
                };

                Ok(inner)
            }
        }
    }

    pub async fn incoming(
        self,
        unix_socket_permission: u32,
        max_requests: usize,
        socket_name: Option<String>,
    ) -> std::io::Result<Incoming> {
        // Check for systemd sockets.
        let systemd_socket = get_systemd_socket(socket_name)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

        match (systemd_socket, self) {
            // Prefer use of systemd sockets.
            (_, Connector::Fd { fd }) | (Some(fd), _) => fd_to_listener(fd, max_requests),

            (None, Connector::Unix { socket_path }) => {
                match std::fs::remove_file(&*socket_path) {
                    Ok(()) => (),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => (),
                    Err(err) if err.raw_os_error() == Some(libc::EISDIR) => {
                        log::warn!("Could not remove socket file because it is a directory. Removing directory.");
                        std::fs::remove_dir_all(&*socket_path)?;
                    }
                    Err(err) => return Err(err),
                }

                let listener = tokio::net::UnixListener::bind(socket_path.clone())?;

                std::fs::set_permissions(
                    socket_path.as_ref(),
                    <std::fs::Permissions as std::os::unix::prelude::PermissionsExt>::from_mode(
                        unix_socket_permission,
                    ),
                )?;

                Ok(Incoming::Unix {
                    listener,
                    max_requests,
                    user_state: Default::default(),
                })
            }

            (None, Connector::Tcp { host, port }) => {
                if cfg!(debug_assertions) {
                    let listener = tokio::net::TcpListener::bind((&*host, port)).await?;
                    Ok(Incoming::Tcp { listener })
                } else {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "servers can only use `unix://` connectors, not `http://` connectors",
                    ))
                }
            }
        }
    }

    fn to_url(&self) -> Result<url::Url, String> {
        match self {
            Connector::Tcp { host, port } => {
                let url = format!("http://{host}:{port}");
                let mut url: url::Url = url.parse().expect("hard-coded URL parses successfully");
                url.set_host(Some(host))
                    .map_err(|err| format!("could not set host {host:?}: {err:?}"))?;
                if *port != 80 {
                    url.set_port(Some(*port))
                        .map_err(|()| format!("could not set port {port:?}"))?;
                }
                Ok(url)
            }

            Connector::Unix { socket_path } => {
                let socket_path = socket_path.to_str().ok_or_else(|| {
                    format!(
                        "socket path {} cannot be serialized as a utf-8 string",
                        socket_path.display()
                    )
                })?;

                let mut url: url::Url = "unix:///unix-socket"
                    .parse()
                    .expect("hard-coded URL parses successfully");
                url.set_path(socket_path);
                Ok(url)
            }

            Connector::Fd { fd } => {
                let fd_path = format!("fd://{fd}");

                let url = url::Url::parse(&fd_path).expect("hard-coded URL parses successfully");

                Ok(url)
            }
        }
    }
}

impl std::fmt::Display for Connector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let url = self.to_url().map_err(|_| std::fmt::Error)?;
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

            Connector::Fd { fd } => {
                let fd = *fd;

                let f = async move {
                    if is_unix_fd(fd)? {
                        let stream: std::os::unix::net::UnixStream =
                            unsafe { std::os::unix::io::FromRawFd::from_raw_fd(fd) };

                        stream.set_nonblocking(true)?;
                        let stream = tokio::net::UnixStream::from_std(stream)?;

                        Ok(AsyncStream::Unix(stream))
                    } else {
                        let stream: std::net::TcpStream =
                            unsafe { std::os::unix::io::FromRawFd::from_raw_fd(fd) };

                        stream.set_nonblocking(true)?;
                        let stream = tokio::net::TcpStream::from_std(stream)?;

                        Ok(AsyncStream::Tcp(stream))
                    }
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
        let url = self.to_url().map_err(serde::ser::Error::custom)?;
        url.to_string().serialize(serializer)
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

impl tokio::io::AsyncRead for AsyncStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match &mut *self {
            AsyncStream::Tcp(inner) => std::pin::Pin::new(inner).poll_read(cx, buf),
            AsyncStream::Unix(inner) => std::pin::Pin::new(inner).poll_read(cx, buf),
        }
    }
}

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

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<std::io::Result<usize>> {
        match &mut *self {
            AsyncStream::Tcp(inner) => std::pin::Pin::new(inner).poll_write_vectored(cx, bufs),
            AsyncStream::Unix(inner) => std::pin::Pin::new(inner).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            AsyncStream::Tcp(inner) => inner.is_write_vectored(),
            AsyncStream::Unix(inner) => inner.is_write_vectored(),
        }
    }
}

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
    inner: Box<dyn std::error::Error + Send + Sync + 'static>,
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

/// Returns `true` if the given fd is a Unix socket; `false` if the given fd is a TCP socket.
///
/// Returns an Err if the socket type is invalid. TCP sockets are only valid for debug builds,
/// so this function returns an Err for release builds using a TCP socket.
fn is_unix_fd(fd: std::os::unix::io::RawFd) -> std::io::Result<bool> {
    let sock_addr = nix::sys::socket::getsockname::<SockaddrStorage>(fd)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    match sock_addr.family() {
        Some(AddressFamily::Unix) => Ok(true),

        // Only debug builds can set up HTTP servers. Release builds must use unix sockets.
        Some(AddressFamily::Inet | AddressFamily::Inet6) if cfg!(debug_assertions) => Ok(false),

        family => Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("systemd socket has unsupported address family {family:?}"),
        )),
    }
}

/// Get the value of the `LISTEN_FDS` or `LISTEN_FDNAMES` environment variable.
///
/// Checks the `LISTEN_PID` variable to ensure that the requested environment variable is for this process.
fn get_env(env: &str) -> Result<Option<String>, String> {
    // Check that the LISTEN_* environment variable is for this process.
    let listen_pid = {
        let listen_pid = match std::env::var("LISTEN_PID") {
            Ok(listen_pid) => listen_pid,
            Err(std::env::VarError::NotPresent) => return Ok(None),
            Err(err @ std::env::VarError::NotUnicode(_)) => {
                return Err(format!("could not read LISTEN_PID env var: {err}"))
            }
        };

        let listen_pid = listen_pid
            .parse()
            .map_err(|err| format!("could not read LISTEN_PID env var: {err}"))?;

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

    // Get the requested environment variable.
    match std::env::var(env) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err @ std::env::VarError::NotUnicode(_)) => {
            Err(format!("could not read {env} env var: {err}"))
        }
    }
}

fn socket_name_to_fd(name: &str) -> Result<std::os::unix::io::RawFd, String> {
    let Some(listen_fdnames) = get_env("LISTEN_FDNAMES")? else { return Err("LISTEN_FDNAMES not found".to_string()) };

    let listen_fdnames: Vec<&str> = listen_fdnames.split(':').collect();

    let index: std::os::unix::io::RawFd =
        match listen_fdnames.iter().position(|&fdname| fdname == name) {
            Some(index) => match index.try_into() {
                Ok(index) => index,
                Err(_) => return Err("couldn't convert LISTEN_FDNAMES index to fd".to_string()),
            },
            None => return Err(format!("socket {name} not found")),
        };

    // The index in LISTEN_FDNAMES is an offset from SD_LISTEN_FDS_START.
    let fd = index + SD_LISTEN_FDS_START;

    Ok(fd)
}

fn fd_to_listener(fd: std::os::unix::io::RawFd, max_requests: usize) -> std::io::Result<Incoming> {
    if is_unix_fd(fd)? {
        let listener: std::os::unix::net::UnixListener =
            unsafe { std::os::unix::io::FromRawFd::from_raw_fd(fd) };
        listener.set_nonblocking(true)?;
        let listener = tokio::net::UnixListener::from_std(listener)?;
        Ok(Incoming::Unix {
            listener,
            max_requests,
            user_state: Default::default(),
        })
    } else {
        let listener: std::net::TcpListener =
            unsafe { std::os::unix::io::FromRawFd::from_raw_fd(fd) };
        listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(listener)?;
        Ok(Incoming::Tcp { listener })
    }
}

/// Return a matching systemd socket. Checks if this process has been socket-activated.
///
/// This mimics `sd_listen_fds` from libsystemd, then returns the fd of systemd socket.
fn get_systemd_socket(
    socket_name: Option<String>,
) -> Result<Option<std::os::unix::io::RawFd>, String> {
    // Ref: <https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html>
    //
    // Try to find a systemd socket to match when non "fd" path has been provided.
    // We consider 4 cases:
    // 1. When there is only 1 socket. In this case, we can ignore the socket name. It means
    // the call is made by identity service which uses only one systemd socket. So matching is simple
    // 2. There are > 1 systemd sockets and a socket name is provided. It means edged is telling us to match an fd with the provided socket name.
    // 3. There are > 1 systemd sockets and a socket name is provided but no LISTEN_FDNAMES. We can't match.
    // 4. There are > 1 systemd sockets but no socket name is provided. In this case it means there is no corresponding systemd socket we should match
    //
    // >sd_listen_fds parses the number passed in the $LISTEN_FDS environment variable, then sets the FD_CLOEXEC flag
    // >for the parsed number of file descriptors starting from SD_LISTEN_FDS_START. Finally, it returns the parsed number.
    //
    // Note that it's not possible to distinguish between fd numbers if a process requires more than one socket.
    // That is why in edged's case we use the systemd socket name to know which fd the function should return
    // CS/IS/KS currently only expect one socket, so this is fine; but it is not the case for iotedged (mgmt and workload sockets)
    // for example.
    //
    // The complication with LISTEN_FDNAMES is that CentOS 7's systemd is too old and doesn't support it, which
    // would mean CS/IS/KS would have to stop using systemd socket activation on CentOS 7 (just like iotedged). This creates more complications,
    // because now the sockets either have to be placed in /var/lib/aziot (just like iotedged does) which means host modules need to try
    // both /run/aziot and /var/lib/aziot to connect to a service, or the services continue to bind sockets under /run/aziot but have to create
    // /run/aziot themselves on startup with ACLs for all three users and all three groups.

    let listen_fds: std::os::unix::io::RawFd = match get_env("LISTEN_FDS")? {
        Some(listen_fds) => listen_fds
            .parse()
            .map_err(|err| format!("could not read LISTEN_FDS env var: {err}"))?,

        None => return Ok(None),
    };

    // If there is no socket available, no match is possible.
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
                "could not fcntl({fd}, F_SETFD, FD_CLOEXEC): {err}"
            ));
        }
    }

    // If there is only one socket, we know this is the identity service which uses only one socket, so we have a match:
    if listen_fds == 1 {
        return Ok(Some(SD_LISTEN_FDS_START));
    }

    // If there is more than 1 socket and we don't have a socket name to match, this is edged telling us that there is no systemd socket we can match.
    let Some(socket_name) = socket_name else { return Ok(None) };

    // If there is more than one socket, this is edged. We can attempt to match the socket name to systemd.
    // This happens when a unix Uri is provided in the config.toml. Systemd sockets get created nonetheless, so we still prefer to use them.
    // If a socket name is provided but we don't see the env variable LISTEN_FDNAMES, it means we are probably on an older OS, and we can't match either.
    let Some(listen_fdnames) = get_env("LISTEN_FDNAMES")? else { return Ok(None) };
    let listen_fdnames: Vec<&str> = listen_fdnames.split(':').collect();

    let len: std::os::unix::io::RawFd = listen_fdnames
        .len()
        .try_into()
        .map_err(|_| "invalid number of sockets".to_string())?;
    if listen_fds != len {
        return Err(format!(
            "Mismatch, there are {} fds, and {} names",
            listen_fds,
            listen_fdnames.len()
        ));
    }

    if let Some(index) = listen_fdnames
        .iter()
        .position(|fdname| (*fdname).eq(&socket_name))
    {
        let index: std::os::unix::io::RawFd = index
            .try_into()
            .map_err(|_| "invalid number of sockets".to_string())?;
        Ok(Some(SD_LISTEN_FDS_START + index))
    } else {
        Err(format!(
            "Could not find a match for {socket_name} in the fd list"
        ))
    }
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

        #[allow(clippy::single_element_loop)]
        for input in &[
            // unsupported scheme
            "ftp://127.0.0.1",
        ] {
            let input = input.parse().unwrap();
            let _ = super::Connector::new(&input).unwrap_err();
        }
    }
}
