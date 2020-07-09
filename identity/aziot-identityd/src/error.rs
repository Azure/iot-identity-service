// Copyright (c) Microsoft. All rights reserved.

pub enum Error {
    LoadCommonSettings(aziot_common::error::Error),
    LoadSettings(std::io::Error),
    ParseSettings(toml::de::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::LoadCommonSettings(_) => f.write_str("could not load common settings"),
            Error::LoadSettings(_) => f.write_str("could not load settings"),
            Error::ParseSettings(_) => f.write_str("could not parse settings"),
        }
    }
}

impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}", self)?;

        let mut source = std::error::Error::source(self);
        while let Some(err) = source {
            writeln!(f, "caused by: {}", err)?;
            source = err.source();
        }

        Ok(())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::LoadCommonSettings(err) => Some(err),
            Error::LoadSettings(err) => Some(err),
            Error::ParseSettings(err) => Some(err),
        }
    }
}

impl From<aziot_common::error::Error> for Error {
    fn from(err: aziot_common::error::Error) -> Self {
        Error::LoadCommonSettings(err)
    }
}
