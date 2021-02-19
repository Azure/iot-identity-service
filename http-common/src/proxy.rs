// Copyright (c) Microsoft. All rights reserved.

use std::env;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub enum MaybeProxyStream<C> {
    NoProxy(C),
    Proxy(hyper_proxy::ProxyStream<C>),
}

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

impl<C> hyper::client::connect::Connection for MaybeProxyStream<C>
where
    C: AsyncRead + AsyncWrite + Unpin,
{
    fn connected(&self) -> hyper::client::connect::Connected {
        match self {
            MaybeProxyStream::NoProxy(_) => hyper::client::connect::Connected::new(),
            MaybeProxyStream::Proxy(_) => hyper::client::connect::Connected::new().proxy(true),
        }
    }
}

#[derive(Clone)]
pub enum MaybeProxyConnector<C> {
    NoProxy(C),
    Proxy(hyper_proxy::ProxyConnector<C>),
}

impl MaybeProxyConnector<hyper_openssl::HttpsConnector<hyper::client::HttpConnector>> {
    pub fn new(
        proxy_uri: Option<hyper::Uri>,
        identity: Option<(openssl::pkey::PKey<openssl::pkey::Private>, Vec<u8>)>,
    ) -> io::Result<Self> {
        let https_connector = match identity.clone() {
            None => hyper_openssl::HttpsConnector::new()?,
            Some(identity) => {
                let tls_connector = identity_to_tls_connector(identity)?;

                let mut http_connector = hyper::client::HttpConnector::new();
                http_connector.enforce_http(false);
                hyper_openssl::HttpsConnector::with_connector(http_connector, tls_connector)?
            }
        };

        if let Some(proxy_uri) = proxy_uri {
            let proxy = uri_to_proxy(proxy_uri)?;
            let proxy_connector = match identity {
                None => hyper_proxy::ProxyConnector::from_proxy(https_connector, proxy)?,
                Some(identity) => {
                    // DEVNOTE: SslConnectionBuilder::build() consumes the builder. So, we need
                    //          to create two copies of it.
                    let proxy_tls_connector = identity_to_tls_connector(identity)?;

                    let mut proxy_connector =
                        hyper_proxy::ProxyConnector::from_proxy(https_connector, proxy)?;
                    proxy_connector.set_tls(Some(proxy_tls_connector.build()));
                    proxy_connector
                }
            };
            Ok(MaybeProxyConnector::Proxy(proxy_connector))
        } else {
            Ok(MaybeProxyConnector::NoProxy(https_connector))
        }
    }
}

fn identity_to_tls_connector(
    identity: (openssl::pkey::PKey<openssl::pkey::Private>, Vec<u8>),
) -> io::Result<openssl::ssl::SslConnectorBuilder> {
    let (key, certs) = identity;

    let mut tls_connector = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())?;

    let mut device_id_certs = openssl::x509::X509::stack_from_pem(&certs)?.into_iter();
    let client_cert = device_id_certs
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "device identity cert not found"))?;

    tls_connector.set_certificate(&client_cert)?;

    for cert in device_id_certs {
        tls_connector.add_extra_chain_cert(cert.clone())?;
    }

    tls_connector.set_private_key(&key)?;

    Ok(tls_connector)
}

impl<C> hyper::service::Service<http::uri::Uri> for MaybeProxyConnector<C>
where
    C: hyper::service::Service<http::uri::Uri> + Send + Unpin + Clone + 'static,
    C::Response:
        AsyncRead + AsyncWrite + hyper::client::connect::Connection + Send + Unpin + 'static,
    C::Future: Send + 'static,
    C::Error: Into<Box<dyn std::error::Error + Sync + Send>>,
{
    type Response = MaybeProxyStream<C::Response>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let poll_status = match self {
            MaybeProxyConnector::NoProxy(https_connector) => https_connector
                .poll_ready(cx)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
            MaybeProxyConnector::Proxy(proxy_connector) => proxy_connector.poll_ready(cx),
        };

        match poll_status {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn call(&mut self, req: http::uri::Uri) -> Self::Future {
        match self {
            MaybeProxyConnector::NoProxy(https_connector) => {
                let mut https_connector_clone = https_connector.clone();
                Box::pin(async move {
                    let stream = https_connector_clone
                        .call(req)
                        .await
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                    Ok(MaybeProxyStream::NoProxy(stream))
                })
            }
            MaybeProxyConnector::Proxy(proxy_connector) => {
                let mut proxy_connector_clone = proxy_connector.clone();
                Box::pin(async move {
                    let stream = proxy_connector_clone
                        .call(req)
                        .await
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                    Ok(MaybeProxyStream::Proxy(stream))
                })
            }
        }
    }
}

fn uri_to_proxy(uri: hyper::Uri) -> io::Result<hyper_proxy::Proxy> {
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

                headers::Authorization::basic(&username, &password)
            }
            None => headers::Authorization::basic(&username, ""),
        };
        proxy.set_authorization(credentials);
    }

    Ok(proxy)
}

pub fn get_proxy_uri(https_proxy: Option<String>) -> io::Result<Option<hyper::Uri>> {
    let proxy_uri = https_proxy
        .or_else(|| env::var("HTTPS_PROXY").ok())
        .or_else(|| env::var("https_proxy").ok());
    let proxy_uri = match proxy_uri {
        None => None,
        Some(s) => {
            let proxy = s
                .parse::<hyper::Uri>()
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

            // Mask the password in the proxy URI before logging it
            let mut sanitized_proxy = url::Url::parse(&proxy.to_string())
                .map_err(|err| io::Error::new(io::ErrorKind::Other, err))?;

            if sanitized_proxy.password().is_some() {
                sanitized_proxy.set_password(Some("******")).map_err(|()| {
                    io::Error::new(io::ErrorKind::Other, "set proxy password failed")
                })?;
            }
            log::info!("Detected HTTPS proxy server {}", sanitized_proxy);

            Some(proxy)
        }
    };
    Ok(proxy_uri)
}

#[cfg(test)]
mod tests {
    use super::get_proxy_uri;

    #[test]
    fn get_proxy_uri_recognizes_https_proxy() {
        let proxy_val = "https://example.com"
            .to_string()
            .parse::<hyper::Uri>()
            .unwrap()
            .to_string();

        assert_eq!(
            get_proxy_uri(Some(proxy_val.clone()))
                .unwrap()
                .unwrap()
                .to_string(),
            proxy_val
        );
    }

    #[test]
    fn get_proxy_uri_allows_credentials_in_authority() {
        let proxy_val = "https://username:password@example.com/".to_string();
        assert_eq!(
            get_proxy_uri(Some(proxy_val.clone()))
                .unwrap()
                .unwrap()
                .to_string(),
            proxy_val
        );

        let proxy_val = "https://username%2f:password%2f@example.com/".to_string();
        assert_eq!(
            get_proxy_uri(Some(proxy_val.clone()))
                .unwrap()
                .unwrap()
                .to_string(),
            proxy_val
        );
    }
}
