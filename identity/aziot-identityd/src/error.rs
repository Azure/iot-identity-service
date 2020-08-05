// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug)]
pub enum Error {
    Authentication,
    Authorization,
    DeviceNotFound,
    DPSClient(std::io::Error),
    HubClient(std::io::Error),
    ModuleNotFound,
    Internal(InternalError),
    InvalidParameter(&'static str, Box<dyn std::error::Error + Send + Sync>),
}

impl Error {
	pub(crate) fn invalid_parameter<E>(name: &'static str, err: E) -> Self where E: Into<Box<dyn std::error::Error + Send + Sync>> {
		Error::InvalidParameter(name, err.into())
	}
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Authentication => f.write_str("authentication error"),
            Error::Authorization => f.write_str("authorization error"),
            Error::DeviceNotFound => f.write_str("device identity not found"),
            Error::DPSClient(err) => write!(f, "DPS client error: {:?}", err),
            Error::HubClient(err) => write!(f, "Hub client error: {:?}", err),
            Error::ModuleNotFound => f.write_str("module identity not found"),
            Error::Internal(_) => f.write_str("internal error"),
            Error::InvalidParameter(name, _) => write!(f, "parameter {:?} has an invalid value", name),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Authentication |
            Error::Authorization |
            Error::DeviceNotFound |
            Error::ModuleNotFound => None,
            Error::DPSClient(err) |
            Error::HubClient(err) => Some(err),
            Error::Internal(err) => Some(err),
            Error::InvalidParameter(_, err) => Some(&**err),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub enum InternalError {
    InvalidUri(http::uri::InvalidUri),
	LoadKeyOpenslEngine(openssl2::Error),
    LoadSettings(std::io::Error),
    ParseSettings(toml::de::Error),
}

impl std::fmt::Display for InternalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InternalError::InvalidUri(_) => f.write_str("invalid resource uri"),
            InternalError::LoadKeyOpenslEngine(_) => f.write_str("could not load aziot-key-openssl-engine"),
            InternalError::LoadSettings(_) => f.write_str("could not load settings"),
            InternalError::ParseSettings(_) => f.write_str("could not parse settings"),
        }
    }
}

impl std::error::Error for InternalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InternalError::InvalidUri(err) => Some(err),
            InternalError::LoadKeyOpenslEngine(err) => Some(err),
            InternalError::LoadSettings(err) => Some(err),
            InternalError::ParseSettings(err) => Some(err),
        }
    }
}
