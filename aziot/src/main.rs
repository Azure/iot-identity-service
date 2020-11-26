// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms)]
#![warn(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_unit_value,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::clippy::module_name_repetitions
)]

use anyhow::Result;
use structopt::StructOpt;

mod internal;

mod check;
mod check_list;
mod init;

async fn try_main() -> Result<()> {
    let options = StructOpt::from_args();
    match options {
        Options::Init => init::run()?,
        Options::Check(cfg) => check::check(cfg).await?,
        Options::CheckList => check_list::check_list()?,
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
    /// Interactive wizard to get 'aziot' up and running.
    Init,
    /// Check for common config and deployment issues.
    Check(check::CheckCfg),
    /// List the checks that are run for 'aziot check'
    CheckList,
}
