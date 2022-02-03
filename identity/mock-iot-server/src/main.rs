// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]

mod certs;
mod dps;
mod hub;
mod server;

use structopt::StructOpt;

#[derive(StructOpt)]
struct Options {
    #[structopt(long, value_name = "PORT")]
    port: u16,

    #[structopt(long, value_name = "SERVER_CERT_CHAIN")]
    server_cert_chain: std::path::PathBuf,

    #[structopt(long, value_name = "SERVER_KEY")]
    server_key: std::path::PathBuf,

    #[structopt(long, value_name = "TRUST_BUNDLE_CERTS_DIR")]
    trust_bundle_certs_dir: Option<std::path::PathBuf>,

    #[structopt(long)]
    enable_identity_certs: bool,

    #[structopt(long)]
    enable_server_certs: bool,
}

#[tokio::main]
async fn main() {
    let options = Options::from_args();

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
