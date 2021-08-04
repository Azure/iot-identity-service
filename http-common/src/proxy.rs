// Copyright (c) Microsoft. All rights reserved.

use std::env;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::{io, io::IoSlice};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub enum MaybeProxyStream<S> {
    NoProxy(S),
    Proxy(hyper_proxy::ProxyStream<S>),
}

impl<S> AsyncRead for MaybeProxyStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
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

impl<S> AsyncWrite for MaybeProxyStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
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

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        match &mut *self {
            MaybeProxyStream::NoProxy(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            MaybeProxyStream::Proxy(s) => Pin::new(s).poll_write_vectored(cx, bufs),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            MaybeProxyStream::NoProxy(s) => s.is_write_vectored(),
            MaybeProxyStream::Proxy(s) => s.is_write_vectored(),
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

impl<S> hyper::client::connect::Connection for MaybeProxyStream<S>
where
    S: hyper::client::connect::Connection,
    hyper_proxy::ProxyStream<S>: hyper::client::connect::Connection,
{
    fn connected(&self) -> hyper::client::connect::Connected {
        match self {
            MaybeProxyStream::NoProxy(stream) => stream.connected(),
            MaybeProxyStream::Proxy(stream) => stream.connected(),
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
        identity: Option<(&openssl::pkey::PKeyRef<openssl::pkey::Private>, &[u8])>,
        trusted_certs: &[openssl::x509::X509],
    ) -> io::Result<Self> {
        let mut http_connector = hyper::client::HttpConnector::new();
        http_connector.enforce_http(false);

        let tls_connector = make_tls_connector(identity, trusted_certs)?;

        let https_connector =
            hyper_openssl::HttpsConnector::with_connector(http_connector, tls_connector)?;

        if let Some(proxy_uri) = proxy_uri {
            let proxy = uri_to_proxy(proxy_uri)?;

            let mut proxy_connector =
                hyper_proxy::ProxyConnector::from_proxy(https_connector, proxy)?;

            // There are two TLS connectors involved with a proxy:
            //
            // - the connector used to connect to the proxy itself
            // - the connector used to connect to the proxied destination
            //
            // We don't have separate configuration of TLS client identity and trusted certs for these two,
            // so we apply the same config to both. Therefore, we create a new `openssl::ssl::SslConnectorBuilder`
            // identical to the original `tls_connector` and use that with `proxy_connector.set_tls`
            //
            // `tls_connector` was already consumed by `hyper_openssl::HttpsConnector::with_connector`
            // and doesn't impl `Clone`, so the new one has to be built from scratch via `make_tls_connector`
            let proxy_tls_connector = make_tls_connector(identity, trusted_certs)?;
            proxy_connector.set_tls(Some(proxy_tls_connector.build()));

            Ok(MaybeProxyConnector::Proxy(proxy_connector))
        } else {
            Ok(MaybeProxyConnector::NoProxy(https_connector))
        }
    }
}

fn make_tls_connector(
    identity: Option<(&openssl::pkey::PKeyRef<openssl::pkey::Private>, &[u8])>,
    trusted_certs: &[openssl::x509::X509],
) -> io::Result<openssl::ssl::SslConnectorBuilder> {
    let mut tls_connector = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())?;

    let cert_store = tls_connector.cert_store_mut();
    for trusted_cert in trusted_certs {
        if let Err(err) = cert_store.add_cert(trusted_cert.clone()) {
            // openssl 1.0 raises X509_R_CERT_ALREADY_IN_HASH_TABLE if a duplicate cert is added to a cert store. [1]
            // 1.1 silently ignores the duplicate. [2]
            //
            // Trusted certs can come from the user, and it's benign to ignore such duplicate certs, so we want to ignore it too.
            //
            // native-tls's implementation ignores *all errors* [3]. But we would like to check and just ignore this particular one.
            //
            // [1]: https://github.com/openssl/openssl/blob/OpenSSL_1_0_2u/crypto/x509/x509_lu.c#L370-L375
            // [2]: https://github.com/openssl/openssl/blob/OpenSSL_1_1_1k/crypto/x509/x509_lu.c#L354-L355
            // [3]: https://github.com/sfackler/rust-native-tls/blob/41522daa6f6e76182c3118a7f9c23f6949e6d59f/src/imp/openssl.rs#L272-L274
            let is_duplicate_cert_error = err.errors().iter().any(|err| {
                // https://github.com/openssl/openssl/blob/OpenSSL_1_0_2u/crypto/err/err.h#L171
                // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1k/include/openssl/err.h#L64
                const ERR_LIB_X509: std::os::raw::c_int = 11;
                // https://github.com/openssl/openssl/blob/OpenSSL_1_0_2u/crypto/x509/x509.h#L1280
                // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1k/include/openssl/x509err.h#L73
                const X509_F_X509_STORE_ADD_CERT: std::os::raw::c_int = 124;
                // https://github.com/openssl/openssl/blob/OpenSSL_1_0_2u/crypto/x509/x509.h#L1296
                // https://github.com/openssl/openssl/blob/OpenSSL_1_1_1k/include/openssl/x509err.h#L95
                const X509_R_CERT_ALREADY_IN_HASH_TABLE: std::os::raw::c_int = 101;

                let code = err.code();
                let library = openssl_sys::ERR_GET_LIB(code);
                let function = openssl_sys::ERR_GET_FUNC(code);
                let reason = openssl_sys::ERR_GET_REASON(code);
                library == ERR_LIB_X509
                    && function == X509_F_X509_STORE_ADD_CERT
                    && reason == X509_R_CERT_ALREADY_IN_HASH_TABLE
            });
            if !is_duplicate_cert_error {
                return Err(err.into());
            }
        }
    }

    if let Some((key, certs)) = identity {
        let mut device_id_certs = openssl::x509::X509::stack_from_pem(certs)?.into_iter();
        let client_cert = device_id_certs.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "device identity cert not found")
        })?;

        tls_connector.set_certificate(&client_cert)?;

        for cert in device_id_certs {
            tls_connector.add_extra_chain_cert(cert)?;
        }

        tls_connector.set_private_key(key)?;
    }

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
        match self {
            MaybeProxyConnector::NoProxy(c) => c
                .poll_ready(cx)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e)),
            MaybeProxyConnector::Proxy(c) => c.poll_ready(cx),
        }
    }

    fn call(&mut self, req: http::uri::Uri) -> Self::Future {
        match self {
            MaybeProxyConnector::NoProxy(c) => {
                let stream = c.call(req);
                Box::pin(async {
                    let stream = stream
                        .await
                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

                    Ok(MaybeProxyStream::NoProxy(stream))
                })
            }
            MaybeProxyConnector::Proxy(c) => {
                let stream = c.call(req);
                Box::pin(async {
                    let stream = stream.await?;

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
