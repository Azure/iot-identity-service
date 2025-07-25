// Copyright (c) Microsoft. All rights reserved.

mod apply;
mod mp;

#[derive(clap::Subcommand)]
pub(crate) enum Options {
    /// Apply the configuration to Identity Service and related services.
    Apply(apply::Options),

    /// Quick-create a new configuration for manual provisioning with a connection string.
    Mp(mp::Options),
}

pub(crate) fn run(options: Options) -> anyhow::Result<()> {
    match options {
        Options::Apply(options) => apply::run(options),
        Options::Mp(options) => mp::run(options),
    }
}
