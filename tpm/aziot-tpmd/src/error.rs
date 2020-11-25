// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug)]
pub enum Error {
    Internal(InternalError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Internal(_) => f.write_str("internal error"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Internal(err) => Some(err),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub enum InternalError {
    ReadConfig(Box<dyn std::error::Error + Send + Sync>),
    InitTpm(aziot_tpm::Error),
    GetTpmKeys(aziot_tpm::Error),
    SignWithAuthKey(aziot_tpm::Error),
    ActivateAuthKey(aziot_tpm::Error),
}

impl std::fmt::Display for InternalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InternalError::ReadConfig(_) => f.write_str("could not read config"),
            InternalError::InitTpm(_) => f.write_str("could not initialize TPM"),
            InternalError::ActivateAuthKey(_) => f.write_str("could not activate with auth key"),
            InternalError::GetTpmKeys(_) => f.write_str("could not get TPM keys"),
            InternalError::SignWithAuthKey(_) => f.write_str("could not sign with auth key"),
        }
    }
}

#[allow(clippy::match_same_arms)]
impl std::error::Error for InternalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InternalError::ReadConfig(err) => Some(&**err),
            InternalError::InitTpm(err) => Some(err),
            InternalError::ActivateAuthKey(err) => Some(err),
            InternalError::GetTpmKeys(err) => Some(err),
            InternalError::SignWithAuthKey(err) => Some(err),
        }
    }
}
