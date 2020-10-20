// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug)]
pub enum Error {
    Internal(InternalError),
    InvalidParameter(&'static str, Box<dyn std::error::Error + Send + Sync>),
}

impl Error {
    pub(crate) fn invalid_parameter<E>(name: &'static str, err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Error::InvalidParameter(name, err.into())
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Internal(_) => f.write_str("internal error"),
            Error::InvalidParameter(name, _) => {
                write!(f, "parameter {:?} has an invalid value", name)
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Internal(err) => Some(err),
            Error::InvalidParameter(_, err) => Some(&**err),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub enum InternalError {
    CreateCert(Box<dyn std::error::Error + Send + Sync>),
    DeleteFile(std::io::Error),
    GetPath(Box<dyn std::error::Error + Send + Sync>),
    LoadKeyOpensslEngine(openssl2::Error),
    ReadConfig(Box<dyn std::error::Error + Send + Sync>),
    ReadFile(std::io::Error),
}

impl std::fmt::Display for InternalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InternalError::CreateCert(_) => f.write_str("could not create cert"),
            InternalError::DeleteFile(_) => f.write_str("could not delete cert file"),
            InternalError::GetPath(_) => {
                f.write_str("could not get file path corresponding to cert ID")
            }
            InternalError::LoadKeyOpensslEngine(_) => {
                f.write_str("could not load aziot-key-openssl-engine")
            }
            InternalError::ReadConfig(_) => f.write_str("could not read config"),
            InternalError::ReadFile(_) => f.write_str("could not read cert file"),
        }
    }
}

impl std::error::Error for InternalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            InternalError::CreateCert(err) => Some(&**err),
            InternalError::DeleteFile(err) => Some(err),
            InternalError::GetPath(err) => Some(&**err),
            InternalError::LoadKeyOpensslEngine(err) => Some(err),
            InternalError::ReadConfig(err) => Some(&**err),
            InternalError::ReadFile(err) => Some(err),
        }
    }
}
