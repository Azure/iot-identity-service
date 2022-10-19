// Copyright (c) Microsoft. All rights reserved.

use std::ffi::{OsStr, OsString};

use anyhow::{anyhow, Result};

use aziotctl_common::system::{
    get_status, get_system_logs, restart, set_log_level, stop, SERVICE_DEFINITIONS,
};

#[derive(clap::Subcommand)]
pub enum Options {
    #[command(about = "Restart the services")]
    Restart,
    #[command(about = "Stop the services")]
    Stop,
    #[command(about = "Report the status of system")]
    Status,
    Logs(LogsOptions),
    SetLogLevel(LogLevelOptions),
    Reprovision(ReprovisionOptions),
}

#[derive(clap::Args)]
#[command(about = "Get logs for the services")]
pub struct LogsOptions {
    /// Extra args to be passed to journalctl
    #[arg(last = true)]
    args: Vec<OsString>,
}

#[derive(clap::Args)]
#[command(about = "Set the log level of the services")]
pub struct LogLevelOptions {
    // NOTE: Possible value references:
    // - https://github.com/rust-lang/log/blob/d6707108c6959ac7b60cdb60a005795ece6d82d6/src/lib.rs#L411
    // - https://github.com/rust-lang/log/blob/d6707108c6959ac7b60cdb60a005795ece6d82d6/src/lib.rs#L473-L487
    // WARN: "off" is excluded from the `FromStr` implementation on
    // `log::Level`:
    // https://github.com/rust-lang/log/blob/d6707108c6959ac7b60cdb60a005795ece6d82d6/src/lib.rs#L481
    #[arg(
        value_parser,
        help = "[possible values: error, warn, info, debug, trace]"
    )]
    log_level: log::Level,
}

#[derive(clap::Args)]
#[command(about = "Reprovision device with IoT Hub")]
pub struct ReprovisionOptions {
    #[cfg(debug_assertions)]
    #[arg(
        value_name = "Identity Service URI",
        long,
        default_value = "unix:///run/aziot/identityd.sock"
    )]
    uri: url::Url,
}

pub async fn system(options: Options) -> Result<()> {
    match options {
        Options::Restart => restart(SERVICE_DEFINITIONS),
        Options::Stop => stop(SERVICE_DEFINITIONS),
        Options::Status => get_status(SERVICE_DEFINITIONS),
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
