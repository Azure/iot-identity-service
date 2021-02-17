// Copyright (c) Microsoft. All rights reserved.

mod wizard;

#[derive(structopt::StructOpt)]
pub(crate) enum Options {
    /// Interactive wizard to get the Azure IoT Identity Service and related services up and running.
    Wizard,
}

#[allow(clippy::needless_pass_by_value)]
pub(crate) fn run(options: Options) -> anyhow::Result<()> {
    match options {
        Options::Wizard => wizard::run(),
    }
}
