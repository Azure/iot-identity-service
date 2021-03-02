// Copyright (c) Microsoft. All rights reserved.

mod apply;
mod wizard;

#[derive(structopt::StructOpt)]
pub(crate) enum Options {
    /// Apply the configuration to the Azure IoT Identity Service and related services.
    Apply(apply::Options),

    /// Interactive wizard to get the Azure IoT Identity Service and related services up and running.
    Wizard,
}

pub(crate) fn run(options: Options) -> anyhow::Result<()> {
    match options {
        Options::Apply(options) => apply::run(options),
        Options::Wizard => wizard::run(),
    }
}
