// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug)]
pub enum Error {
    ReadConfig(
        Option<std::path::PathBuf>,
        Box<dyn std::error::Error + Send + Sync>,
    ),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ReadConfig(Some(path), _) => {
                write!(f, "could not read config from {}", path.display())
            }
            Error::ReadConfig(None, _) => f.write_str("could not read config"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            Error::ReadConfig(_, err) => Some(&**err),
        }
    }
}
