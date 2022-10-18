// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

mod dps;
mod hub;
mod server;

use clap::Parser;

#[derive(Parser)]
struct Options {
    #[arg(long)]
    port: u16,

    #[arg(long)]
    server_cert_chain: std::path::PathBuf,

    #[arg(long)]
    server_key: std::path::PathBuf,
}

#[tokio::main]
async fn main() {
    let options = Options::parse();

    println!(
        "Using server certificate chain {}",
        options.server_cert_chain.to_str().unwrap()
    );
    println!(
        "Using server private key {}",
        options.server_key.to_str().unwrap()
    );

    let server_key = std::fs::read_to_string(&options.server_key).unwrap();
    let server_key = openssl::pkey::PKey::private_key_from_pem(server_key.as_bytes()).unwrap();

    let server_context = crate::server::ContextInner::new(&options);
    let server_context = std::sync::Mutex::new(server_context);
    let server_context = std::sync::Arc::new(server_context);

    println!("Listening on localhost:{}.", options.port);
    let incoming = test_common::tokio_openssl2::Incoming::new(
        "localhost",
        options.port,
        &options.server_cert_chain,
        &server_key,
        false,
    )
    .unwrap();

    let server =
        hyper::Server::builder(incoming).serve(hyper::service::make_service_fn(move |_| {
            let context = server_context.clone();

            let service = hyper::service::service_fn(move |req| {
                crate::server::serve_request(context.clone(), req)
            });

            async move { Ok::<_, std::convert::Infallible>(service) }
        }));

    server.await.unwrap();
}
