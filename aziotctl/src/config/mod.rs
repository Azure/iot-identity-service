// Copyright (c) Microsoft. All rights reserved.

mod apply;

#[derive(structopt::StructOpt)]
pub(crate) enum Options {
    /// Apply the configuration to the Azure IoT Identity Service and related services.
    Apply(apply::Options),
}

pub(crate) fn run(options: Options) -> anyhow::Result<()> {
    match options {
        Options::Apply(options) => apply::run(options),
    }
}
