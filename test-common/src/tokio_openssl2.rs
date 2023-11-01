// Copyright (c) Microsoft. All rights reserved.

type HandshakeFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
            Output = Result<tokio_openssl::SslStream<tokio::net::TcpStream>, openssl::ssl::Error>,
        >,
    >,
>;

/// A stream of incoming TLS connections, for use with a hyper server.
pub struct Incoming {
    listener: tokio::net::TcpListener,
    tls_acceptor: openssl::ssl::SslAcceptor,
    connections: futures_util::stream::FuturesUnordered<HandshakeFuture>,
}

impl Incoming {
    pub fn new(
        addr: &str,
        port: u16,
        cert_chain_path: &std::path::Path,
        private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        verify_client: bool,
    ) -> std::io::Result<Self> {
        let listener = std::net::TcpListener::bind((addr, port))?;
        listener.set_nonblocking(true)?;
        let listener = tokio::net::TcpListener::from_std(listener)?;

        let mut tls_acceptor =
            openssl::ssl::SslAcceptor::mozilla_modern(openssl::ssl::SslMethod::tls())?;
        tls_acceptor.set_certificate_chain_file(cert_chain_path)?;
        tls_acceptor.set_private_key(private_key)?;

        if verify_client {
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
                        "openssl verification result: {openssl_verification_result}"
                    );
                    openssl_verification_result
                },
            );
        }

        let tls_acceptor = tls_acceptor.build();

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
                    let stream = openssl::ssl::Ssl::new(self.tls_acceptor.context())
                        .and_then(|ssl| tokio_openssl::SslStream::new(ssl, stream));
                    let mut stream = match stream {
                        Ok(stream) => stream,
                        Err(err) => {
                            eprintln!(
                                "Dropping client that failed to complete a TLS handshake: {err}"
                            );
                            continue;
                        }
                    };
                    self.connections.push(Box::pin(async move {
                        let () = std::pin::Pin::new(&mut stream).accept().await?;
                        Ok(stream)
                    }));
                }

                std::task::Poll::Ready(Err(err)) => eprintln!(
                    "Dropping client that failed to completely establish a TCP connection: {err}"
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
                    "Dropping client that failed to complete a TLS handshake: {err}"
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
