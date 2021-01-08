// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug)]
pub(crate) struct Error(pub(crate) ErrorKind, pub(crate) backtrace::Backtrace);

#[derive(Debug)]
pub(crate) enum ErrorKind {
    GetProcessName(std::borrow::Cow<'static, str>),
    ReadConfig(config_common::error::Error),
    Service(Box<dyn std::error::Error>),
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErrorKind::GetProcessName(message) => write!(f, "could not read argv[0]: {}", message),
            ErrorKind::ReadConfig(_) => f.write_str("could not read config"),
            ErrorKind::Service(_) => f.write_str("service encountered an error"),
        }
    }
}

impl std::error::Error for ErrorKind {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            ErrorKind::GetProcessName(_) => None,
            ErrorKind::ReadConfig(_) => None,
            ErrorKind::Service(err) => Some(&**err),
        }
    }
}

impl From<ErrorKind> for Error {
    fn from(err: ErrorKind) -> Self {
        Error(err, Default::default())
    }
}
