// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_and_return,
    clippy::let_unit_value,
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::type_complexity
)]

use anyhow::Result;
use structopt::StructOpt;

mod internal;

// Subcommands
mod check;
mod check_list;
mod config;
mod system;

async fn try_main() -> Result<()> {
    let options = StructOpt::from_args();
    match options {
        Options::Check(cfg) => check::check(cfg).await?,
        Options::CheckList(cfg) => check_list::check_list(cfg)?,
        Options::Config(cfg) => config::run(cfg)?,
        Options::System(cfg) => system::system(cfg).await?,
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(err) = try_main().await {
        eprintln!("{:?}", err);
    }
}

#[derive(StructOpt)]
enum Options {
    /// Work with the configuration of the Azure IoT Identity Service and related services.
    Config(config::Options),

    /// Check for common config and deployment issues.
    Check(check::Options),

    /// List the checks that are run for 'aziotctl check'
    CheckList(check_list::Options),

    /// Use system helper commands
    System(system::Options),
}
