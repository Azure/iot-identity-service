// Copyright (c) Microsoft. All rights reserved.

use std::{
    error::Error as StdError,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::{Stream as _, stream::FuturesUnordered};
use hyper::{
    body::{Body, Incoming},
    server::conn::http1::Builder,
    service::HttpService,
};
use hyper_util::rt::TokioIo;

type Connection = Pin<Box<dyn Future<Output = Result<(), Box<dyn StdError>>>>>;

/// An HTTP server instance that binds a TLS connection with the given parameters and runs the given hyper service on every accepted connection.
pub struct Server<S> {
    service: S,
    listener: tokio::net::TcpListener,
    tls_acceptor: openssl::ssl::SslAcceptor,
    builder: Builder,
    connections: FuturesUnordered<Connection>,
}

impl<S> Server<S> {
    pub fn new(
        addr: &str,
        port: u16,
        cert_chain_path: &std::path::Path,
        private_key: &openssl::pkey::PKey<openssl::pkey::Private>,
        verify_client: bool,
        service: S,
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
                    println!("openssl verification result: {openssl_verification_result}");
                    openssl_verification_result
                },
            );
        }

        let tls_acceptor = tls_acceptor.build();

        let builder = Builder::new();

        Ok(Self {
            service,
            listener,
            tls_acceptor,
            builder,
            connections: Default::default(),
        })
    }
}

impl<S> Future for Server<S>
where
    Self: Unpin,
    S: Clone + HttpService<Incoming> + 'static,
    S::Error: Into<Box<dyn StdError + Send + Sync>>,
    S::ResBody: 'static,
    <S::ResBody as Body>::Error: Into<Box<dyn StdError + Send + Sync>>,
{
    type Output = Result<(), Box<dyn StdError + Send + Sync>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            match self.listener.poll_accept(cx) {
                Poll::Ready(Ok((stream, _))) => {
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

                    let builder = self.builder.clone();
                    let service = self.service.clone();
                    self.connections.push(Box::pin(async move {
                        println!("Accepted connection from client");
                        () = Pin::new(&mut stream).accept().await?;
                        () = builder
                            .serve_connection(TokioIo::new(stream), service)
                            .await?;
                        Ok(())
                    }));
                }

                Poll::Ready(Err(err)) => eprintln!("Dropping client: {err}"),

                Poll::Pending => break,
            }
        }

        loop {
            match Pin::new(&mut self.connections).poll_next(cx) {
                Poll::Ready(Some(Ok(()))) => println!("Client disconnected"),
                Poll::Ready(Some(Err(err))) => eprintln!("Disconnected client due to error: {err}"),
                Poll::Ready(None) | Poll::Pending => return Poll::Pending,
            }
        }
    }
}
