// Copyright (c) Microsoft. All rights reserved.

use log::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run().await?;

    Ok(())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    read_is_settings()?;
    aziot_identityd::Server::new()?;

    info!("Identity Service starting..");

    info!("Identity Service stopped.");

    Ok(())
}

fn read_is_settings() -> Result<aziot_identityd::settings::Settings, Box<dyn std::error::Error>> {
    let settings = aziot_identityd::app::init()?;
    Ok(settings)
}
