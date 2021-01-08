// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug)]
pub struct Error(pub(crate) ErrorKind, pub(crate) backtrace::Backtrace);

#[derive(Debug)]
pub enum ErrorKind {
    ReadConfig(Option<std::path::PathBuf>, Box<dyn std::error::Error>),
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::ReadConfig(Some(path), _) => {
                write!(f, "could not read config from {}", path.display())
            }
            ErrorKind::ReadConfig(None, _) => f.write_str("could not read config"),
        }
    }
}

impl std::error::Error for ErrorKind {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            ErrorKind::ReadConfig(_, err) => Some(&**err),
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(err: ErrorKind) -> Self {
        Error(err, Default::default())
    }
}
