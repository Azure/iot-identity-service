// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::let_unit_value,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::type_complexity
)]

mod init;

fn main() -> Result<(), Error> {
    let options = structopt::StructOpt::from_args();
    match options {
        Options::Init => init::run()?,
    }

    Ok(())
}

#[derive(structopt::StructOpt)]
enum Options {
    Init,
}

struct Error(Box<dyn std::error::Error>, backtrace::Backtrace);

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self.0)?;

        let mut source = self.0.source();
        while let Some(err) = source {
            writeln!(f, "caused by: {}", err)?;
            source = err.source();
        }

        writeln!(f, "{:?}", self.1)?;

        Ok(())
    }
}

impl<E> From<E> for Error
where
    E: Into<Box<dyn std::error::Error>>,
{
    fn from(err: E) -> Self {
        Error(err.into(), Default::default())
    }
}
