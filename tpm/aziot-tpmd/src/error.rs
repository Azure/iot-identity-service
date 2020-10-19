// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug)]
pub enum Error {
    Internal(InternalError),
    InvalidParameter(Option<(&'static str, Box<dyn std::error::Error + Send + Sync>)>),
}

impl Error {
    // pub(crate) fn invalid_parameter<E>(name: &'static str, err: E) -> Self
    // where
    //     E: Into<Box<dyn std::error::Error + Send + Sync>>,
    // {
    //     Error::InvalidParameter(Some((name, err.into())))
    // }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Internal(_) => f.write_str("internal error"),
            Error::InvalidParameter(Some((name, _))) => {
                write!(f, "parameter {:?} has an invalid value", name)
            }
            Error::InvalidParameter(None) => f.write_str("a parameter has an invalid value"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Internal(err) => Some(err),
            Error::InvalidParameter(Some((_, err))) => Some(&**err),
            Error::InvalidParameter(None) => None,
        }
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub enum InternalError {
    GetTpmKeys(aziot_tpm::Error),
    InitTpm(aziot_tpm::Error),
    ReadConfig(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for InternalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InternalError::GetTpmKeys(_) => f.write_str("could not get TPM keys"),
            InternalError::InitTpm(_) => f.write_str("could not initialize TPM"),
            InternalError::ReadConfig(_) => f.write_str("could not read config"),
        }
    }
}

#[allow(clippy::match_same_arms)]
impl std::error::Error for InternalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InternalError::GetTpmKeys(err) => Some(err),
            InternalError::InitTpm(err) => Some(err),
            InternalError::ReadConfig(err) => Some(&**err),
        }
    }
}
