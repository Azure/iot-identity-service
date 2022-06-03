// Copyright (c) Microsoft. All rights reserved.

use std::ffi::{OsStr, OsString};

use anyhow::{anyhow, Result};
use structopt::StructOpt;

use aziotctl_common::system::{
    get_status, get_system_logs, restart, set_log_level, stop, SERVICE_DEFINITIONS,
};

#[derive(StructOpt)]
pub enum Options {
    Restart(RestartOptions),
    Stop(StopOptions),
    Status(StatusOptions),
    Logs(LogsOptions),
    SetLogLevel(LogLevelOptions),
    Reprovision(ReprovisionOptions),
}

#[derive(StructOpt)]
#[structopt(about = "Restart the services")]
pub struct RestartOptions {}

#[derive(StructOpt)]
#[structopt(about = "Stop the services")]
pub struct StopOptions {}

#[derive(StructOpt)]
#[structopt(about = "Report the status of system")]
pub struct StatusOptions {}

#[derive(StructOpt)]
#[structopt(about = "Get logs for the services")]
pub struct LogsOptions {
    /// Extra args to be passed to journalctl
    #[structopt(last = true)]
    args: Vec<OsString>,
}

#[derive(StructOpt)]
#[structopt(about = "Set the log level of the services")]
pub struct LogLevelOptions {
    #[structopt(value_name = r#"One of "trace", "debug", "info", "warn", or "error""#)]
    log_level: log::Level,
}

#[derive(StructOpt)]
#[structopt(about = "Reprovision device with IoT Hub")]
pub struct ReprovisionOptions {
    #[cfg(debug_assertions)]
    #[structopt(
        value_name = "Identity Service URI",
        long,
        default_value = "unix:///run/aziot/identityd.sock"
    )]
    uri: url::Url,
}

pub async fn system(options: Options) -> Result<()> {
    match options {
        Options::Restart(_) => restart(SERVICE_DEFINITIONS),
        Options::Stop(_) => stop(SERVICE_DEFINITIONS),
        Options::Status(_) => get_status(SERVICE_DEFINITIONS),
        Options::Logs(opts) => logs(&opts),
        Options::SetLogLevel(opts) => set_log_level(SERVICE_DEFINITIONS, opts.log_level),

        #[cfg(debug_assertions)]
        Options::Reprovision(opts) => reprovision(&opts.uri).await,

        #[cfg(not(debug_assertions))]
        Options::Reprovision(_) => {
            reprovision(
                &url::Url::parse("unix:///run/aziot/identityd.sock")
                    .expect("hard-coded URI should parse"),
            )
            .await
        }
    }
}

fn logs(options: &LogsOptions) -> Result<()> {
    let services: Vec<&str> = SERVICE_DEFINITIONS.iter().map(|s| s.service).collect();
    let args: Vec<&OsStr> = options.args.iter().map(AsRef::as_ref).collect();

    get_system_logs(&services, &args)
}

async fn reprovision(uri: &url::Url) -> Result<()> {
    let connector =
        http_common::Connector::new(uri).map_err(|err| anyhow!("Invalid URI {}: {}", uri, err))?;
    let client = aziot_identity_client_async::Client::new(
        aziot_identity_common_http::ApiVersion::V2021_12_01,
        connector,
        0,
    );

    match client.reprovision().await {
        Ok(_) => {
            println!("Successfully reprovisioned with IoT Hub.");
            Ok(())
        }

        Err(err) => Err(anyhow!("Failed to reprovision: {}", err)),
    }
}
