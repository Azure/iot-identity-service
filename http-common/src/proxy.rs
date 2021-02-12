// Copyright (c) Microsoft. All rights reserved.

use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(feature = "tokio1")]
pub enum MaybeProxyStream<C> {
    NoProxy(hyper_openssl::MaybeHttpsStream<C>),
    Proxy(hyper_proxy::ProxyStream<hyper_openssl::MaybeHttpsStream<C>>),
}

#[cfg(feature = "tokio1")]
impl<C> AsyncRead for MaybeProxyStream<C>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeProxyStream::NoProxy(s) => Pin::new(s).poll_read(cx, buf),
            MaybeProxyStream::Proxy(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

#[cfg(feature = "tokio1")]
impl<C> AsyncWrite for MaybeProxyStream<C>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            MaybeProxyStream::NoProxy(s) => Pin::new(s).poll_write(ctx, buf),
            MaybeProxyStream::Proxy(s) => Pin::new(s).poll_write(ctx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeProxyStream::NoProxy(s) => Pin::new(s).poll_flush(ctx),
            MaybeProxyStream::Proxy(s) => Pin::new(s).poll_flush(ctx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            MaybeProxyStream::NoProxy(s) => Pin::new(s).poll_shutdown(ctx),
            MaybeProxyStream::Proxy(s) => Pin::new(s).poll_shutdown(ctx),
        }
    }
}

#[cfg(feature = "tokio1")]
pub enum MaybeProxyConnector<C> {
    NoProxy(hyper_openssl::HttpsConnector<C>),
    Proxy(hyper_proxy::ProxyConnector<hyper_openssl::HttpsConnector<C>>),
}

#[cfg(feature = "tokio1")]
impl MaybeProxyConnector<hyper::client::HttpConnector> {
    pub fn build(
        proxy_uri: Option<hyper::Uri>,
        identity: Option<(openssl::pkey::PKey<openssl::pkey::Private>, Vec<u8>)>,
    ) -> io::Result<Self> {
        let mut http_connector = hyper::client::HttpConnector::new();

        if let Some(proxy_uri) = proxy_uri {
            let proxy = uri_to_proxy(proxy_uri)?;
            let proxy_connector = match identity {
                None => {
                    let https_connector = hyper_openssl::HttpsConnector::new()?;
                    hyper_proxy::ProxyConnector::from_proxy(https_connector, proxy)?
                }
                Some((key, certs)) => {
                    // DEVNOTE: SslConnectionBuilder::build() consumes the builder. So, we need
                    //          to create two copies of it.
                    let mut tls_connector =
                        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())?;
                    let mut proxy_tls_connector =
                        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())?;
                    let connectors = vec![tls_connector, proxy_tls_connector];

                    let device_id_certs = openssl::x509::X509::stack_from_pem(&certs)?.into_iter();
                    let client_cert = device_id_certs.next().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::Other, "device identity cert not found")
                    })?;

                    for connector in connectors {
                        connector.set_certificate(&client_cert)?;

                        for cert in device_id_certs {
                            connector.add_extra_chain_cert(cert.clone())?;
                        }

                        connector.set_private_key(&key);
                    }

                    let mut http_connector = hyper::client::HttpConnector::new();
                    http_connector.enforce_http(false);
                    let tls_connector = hyper_openssl::HttpsConnector::with_connector(
                        http_connector,
                        tls_connector,
                    )?;
                    let proxy_connector =
                        hyper_proxy::ProxyConnector::from_proxy(tls_connector, proxy)?;
                    proxy_connector.set_tls(Some(proxy_tls_connector.build()));
                    proxy_connector
                }
            };
            Ok(MaybeProxyConnector::Proxy(proxy_connector))
        } else {
            let https_connector = hyper_openssl::HttpsConnector::new()?;
            Ok(MaybeProxyConnector::NoProxy(https_connector))
        }
    }
}

#[cfg(feature = "tokio1")]
impl<C> hyper::service::Service<http::uri::Uri> for MaybeProxyConnector<C>
where
    C: hyper::service::Service<http::uri::Uri> + Send + Unpin + 'static,
    C::Response:
        AsyncRead + AsyncWrite + hyper::client::connect::Connection + Send + Unpin + 'static,
    C::Future: Send + 'static,
    C::Error: Into<Box<dyn std::error::Error + Sync + Send>>,
{
    type Response = MaybeProxyStream<C::Response>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::uri::Uri) -> Self::Future {
        match *self {
            MaybeProxyConnector::NoProxy(https_stream) => Box::pin(async move {
                match Pin::new(&mut https_stream).call(req).await {
                    Ok(connect) => Ok(MaybeProxyStream::NoProxy(connect)),
                    Err(e) => Err(io::Error::new(io::ErrorKind::Other, e).into()),
                }
            }),
            MaybeProxyConnector::Proxy(proxy_stream) => Box::pin(async move {
                match Pin::new(&mut proxy_stream).call(req).await {
                    Ok(connect) => Ok(MaybeProxyStream::Proxy(connect)),
                    Err(e) => Err(io::Error::new(io::ErrorKind::Other, e).into()),
                }
            }),
        }
    }
}

#[cfg(feature = "tokio1")]
pub fn uri_to_proxy(uri: hyper::Uri) -> io::Result<hyper_proxy::Proxy> {
    let proxy_url =
        url::Url::parse(&uri.to_string()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let mut proxy = hyper_proxy::Proxy::new(hyper_proxy::Intercept::All, uri);

    if !proxy_url.username().is_empty() {
        let username = percent_encoding::percent_decode_str(proxy_url.username())
            .decode_utf8()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        let credentials = match proxy_url.password() {
            Some(password) => {
                let password = percent_encoding::percent_decode_str(password)
                    .decode_utf8()
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                typed_headers::Credentials::basic(&username, &password)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            }
            None => typed_headers::Credentials::basic(&username, "")
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
        };
        proxy.set_authorization(credentials);
    }

    Ok(proxy)
}
