// Copyright (c) Microsoft. All rights reserved.

pub(crate) async fn connect(
    stream: std::net::TcpStream,
    cert_chain_path: &std::path::Path,
    private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    domain: &str,
) -> std::io::Result<bytes::BytesMut> {
    use futures_util::StreamExt;

    let stream = tokio::net::TcpStream::from_std(stream)?;

    let mut tls_connector = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())?;
    tls_connector.set_certificate_chain_file(cert_chain_path)?;
    tls_connector.set_private_key(private_key)?;

    // The root of the client cert is the CA, and we expect the server cert to be signed by this same CA.
    // So add it to the cert store.
    let ca_cert = {
        let cert_chain_file = std::fs::read(cert_chain_path)?;
        let mut cert_chain = openssl::x509::X509::stack_from_pem(&cert_chain_file)?;
        cert_chain.pop().unwrap()
    };
    tls_connector.cert_store_mut().add_cert(ca_cert)?;

    // Log the server cert chain. Does not change the verification result from what openssl already concluded.
    tls_connector.set_verify_callback(
        openssl::ssl::SslVerifyMode::PEER,
        |openssl_verification_result, context| {
            println!("Server cert:");
            let chain = context.chain().unwrap();
            for (i, cert) in chain.into_iter().enumerate() {
                println!(
                    "    #{}: {}",
                    i + 1,
                    cert.subject_name()
                        .entries()
                        .next()
                        .unwrap()
                        .data()
                        .as_utf8()
                        .unwrap()
                );
            }
            println!(
                "openssl verification result: {}",
                openssl_verification_result
            );
            openssl_verification_result
        },
    );

    let tls_connector = tls_connector.build();

    let stream = tokio_openssl::connect(tls_connector.configure()?, domain, stream)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let (mut send_request, connection) = hyper::client::conn::handshake(stream)
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;

    let mut request = hyper::Request::new(Default::default());
    *request.uri_mut() = hyper::Uri::from_static("/");
    let send_request = send_request.send_request(request);

    let connection = connection.without_shutdown();
    let _ = tokio::spawn(connection);

    let response = send_request
        .await
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
    let mut response_body = response.into_body();

    let mut response = bytes::BytesMut::new();

    while let Some(chunk) = response_body.next().await {
        let chunk = chunk.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
        response.extend_from_slice(&chunk);
    }

    Ok(response)
}

type HandshakeFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
            Output = Result<
                tokio_openssl::SslStream<tokio::net::TcpStream>,
                tokio_openssl::HandshakeError<tokio::net::TcpStream>,
            >,
        >,
    >,
>;

/// A stream of incoming TLS connections, for use with a hyper server.
pub(crate) struct Incoming {
    listener: tokio::net::TcpListener,
    tls_acceptor: std::sync::Arc<openssl::ssl::SslAcceptor>,
    connections: futures_util::stream::FuturesUnordered<HandshakeFuture>,
}

impl Incoming {
    pub(crate) fn new(
        listener: std::net::TcpListener,
        cert_chain_path: &std::path::Path,
        private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
    ) -> std::io::Result<Self> {
        let listener = tokio::net::TcpListener::from_std(listener)?;

        let mut tls_acceptor =
            openssl::ssl::SslAcceptor::mozilla_modern(openssl::ssl::SslMethod::tls())?;
        tls_acceptor.set_certificate_chain_file(cert_chain_path)?;
        tls_acceptor.set_private_key(private_key)?;

        // The root of the server cert is the CA, and we expect the client cert to be signed by this same CA.
        // So add it to the cert store.
        let ca_cert = {
            let cert_chain_file = std::fs::read(cert_chain_path)?;
            let mut cert_chain = openssl::x509::X509::stack_from_pem(&cert_chain_file)?;
            cert_chain.pop().unwrap()
        };
        tls_acceptor.cert_store_mut().add_cert(ca_cert)?;

        // Log the client cert chain. Does not change the verification result from what openssl already concluded.
        tls_acceptor.set_verify_callback(
            openssl::ssl::SslVerifyMode::PEER,
            |openssl_verification_result, context| {
                println!("Client cert:");
                let chain = context.chain().unwrap();
                for (i, cert) in chain.into_iter().enumerate() {
                    println!(
                        "    #{}: {}",
                        i + 1,
                        cert.subject_name()
                            .entries()
                            .next()
                            .unwrap()
                            .data()
                            .as_utf8()
                            .unwrap()
                    );
                }
                println!(
                    "openssl verification result: {}",
                    openssl_verification_result
                );
                openssl_verification_result
            },
        );

        let tls_acceptor = tls_acceptor.build();
        let tls_acceptor = std::sync::Arc::new(tls_acceptor);

        Ok(Incoming {
            listener,
            tls_acceptor,
            connections: Default::default(),
        })
    }
}

impl hyper::server::accept::Accept for Incoming {
    type Conn = tokio_openssl::SslStream<tokio::net::TcpStream>;
    type Error = std::io::Error;

    fn poll_accept(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Self::Conn, Self::Error>>> {
        use futures_core::Stream;

        loop {
            match self.listener.poll_accept(cx) {
                std::task::Poll::Ready(Ok((stream, _))) => {
                    // The async fn needs to own the SslAcceptor even though it only uses it as a borrow,
                    // because the future returned by `tokio_openssl::accept` holds on to the borrow
                    // and is thus constrained by the borrow's lifetime.
                    let tls_acceptor = self.tls_acceptor.clone();
                    self.connections.push(Box::pin(async move {
                        tokio_openssl::accept(&tls_acceptor, stream).await
                    }));
                }

                std::task::Poll::Ready(Err(err)) => eprintln!(
                    "Dropping client that failed to completely establish a TCP connection: {}",
                    err
                ),

                std::task::Poll::Pending => break,
            }
        }

        loop {
            if self.connections.is_empty() {
                return std::task::Poll::Pending;
            }

            match std::pin::Pin::new(&mut self.connections).poll_next(cx) {
                std::task::Poll::Ready(Some(Ok(stream))) => {
                    println!("Accepted connection from client");
                    return std::task::Poll::Ready(Some(Ok(stream)));
                }

                std::task::Poll::Ready(Some(Err(err))) => eprintln!(
                    "Dropping client that failed to complete a TLS handshake: {}",
                    err
                ),

                std::task::Poll::Ready(None) => {
                    println!("Shutting down web server");
                    return std::task::Poll::Ready(None);
                }

                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
    }
}
