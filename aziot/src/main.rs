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

use structopt::StructOpt;

mod check;
mod error;
mod init;

pub use error::Error;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let options = StructOpt::from_args();
    match options {
        Options::Init => init::run()?,
        Options::Check(cfg) => check::check(cfg).await?,
        Options::CheckList => check::check_list()?,
    }

    Ok(())
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
