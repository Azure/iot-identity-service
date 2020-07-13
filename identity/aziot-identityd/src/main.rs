// Copyright (c) Microsoft. All rights reserved.

mod http;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run().await?;

    Ok(())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    read_is_settings()?;
    let server = aziot_identityd::Server::new()?;
    let server = std::sync::Arc::new(server);

    log::info!("Identity Service starting..");

    let incoming = hyper::server::conn::AddrIncoming::bind(&"0.0.0.0:8901".parse()?)?;

    let server =
        hyper::Server::builder(incoming)
            .serve(hyper::service::make_service_fn(|_| {
                let server = http::Server { inner: server.clone() };
                futures_util::future::ok::<_, std::convert::Infallible>(server)
            }));
    let () = server.await?;

    log::info!("Identity Service stopped.");

    Ok(())
}

fn read_is_settings() -> Result<aziot_identityd::settings::Settings, Box<dyn std::error::Error>> {
    let settings = aziot_identityd::app::init()?;
    Ok(settings)
}
