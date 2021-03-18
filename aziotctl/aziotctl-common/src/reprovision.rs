// Copyright (c) Microsoft. All rights reserved.

use anyhow::{anyhow, Result};

pub async fn reprovision(uri: &url::Url) -> Result<()> {
    let connector =
        http_common::Connector::new(uri).map_err(|err| anyhow!("Invalid URI {}: {}", uri, err))?;
    let client = aziot_identity_client_async::Client::new(
        aziot_identity_common_http::ApiVersion::V2020_09_01,
        connector,
    );

    match client.reprovision().await {
        Ok(_) => {
            println!("Successfully reprovisioned with IoT Hub.");
            Ok(())
        }

        Err(err) => Err(anyhow!("Failed to reprovision: {}", err)),
    }
}
