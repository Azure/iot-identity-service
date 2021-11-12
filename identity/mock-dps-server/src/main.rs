// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

mod request;
mod server;

#[tokio::main]
async fn main() {
    let matches = clap::App::new("mock-dps-server")
        .arg(
            clap::Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .takes_value(true)
                .required(true)
                .help("localhost port that server listens on"),
        )
        .arg(
            clap::Arg::with_name("server cert chain")
                .long("server-cert-chain")
                .value_name("SERVER_CERT_CHAIN")
                .takes_value(true)
                .required(true)
                .help("path to TLS server cert chain presented to clients"),
        )
        .arg(
            clap::Arg::with_name("server key")
                .long("server-key")
                .value_name("SERVER_KEY")
                .takes_value(true)
                .required(true)
                .help("path to TLS server key"),
        )
        .get_matches();

    let port = matches.value_of("port").unwrap();
    let port: u16 = port.parse().unwrap();

    let server_cert_chain = matches.value_of("server cert chain").unwrap();
    println!("Using server certificate chain {}", server_cert_chain);
    let server_cert_chain = std::path::Path::new(server_cert_chain);

    let server_key = matches.value_of("server key").unwrap();
    println!("Using server private key {}", server_key);
    let server_key = std::fs::read_to_string(server_key).unwrap();
    let server_key = openssl::pkey::PKey::private_key_from_pem(server_key.as_bytes()).unwrap();

    println!("Listening on localhost:{}.", port);
    let incoming = test_common::tokio_openssl2::Incoming::new(
        "localhost",
        port,
        server_cert_chain,
        &server_key,
        false,
    )
    .unwrap();

    let dps_context = crate::server::DpsContextInner::default();
    let dps_context = std::sync::Mutex::new(dps_context);
    let dps_context = std::sync::Arc::new(dps_context);

    let server =
        hyper::Server::builder(incoming).serve(hyper::service::make_service_fn(move |_| {
            let context = dps_context.clone();

            let service = hyper::service::service_fn(move |req| {
                crate::server::serve_request(context.clone(), req)
            });

            async move { Ok::<_, std::convert::Infallible>(service) }
        }));

    server.await.unwrap();
}
