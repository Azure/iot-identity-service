// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug)]
pub enum Error {
    Authentication,
    Authorization,
    DeviceNotFound,
    DpsClient(std::io::Error),
    DpsNotSupportedInNestedMode,
    HubClient(std::io::Error),
    KeyClient(std::io::Error),
    ModuleNotFound,
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

    pub(crate) fn is_network(&self) -> bool {
        match &self {
            Error::DpsClient(err) | Error::HubClient(err) => match err.kind() {
                std::io::ErrorKind::TimedOut => true, // Network timed out
                std::io::ErrorKind::Other => {
                    if let Some(err) = err.get_ref() {
                        // TODO: check if error is hyper::Error
                        return true;
                    }

                    false
                }
                _ => false,
            },

            _ => false,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Authentication => f.write_str("authentication error"),
            Error::Authorization => f.write_str("authorization error"),
            Error::DeviceNotFound => f.write_str("device identity not found"),
            Error::DpsClient(_) => f.write_str("DPS client error"),
            Error::DpsNotSupportedInNestedMode => {
                f.write_str("DPS provisioning is not supported in nested mode")
            }
            Error::HubClient(_) => f.write_str("Hub client error"),
            Error::KeyClient(_) => f.write_str("Key client error"),
            Error::ModuleNotFound => f.write_str("module identity not found"),
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
            Error::Authentication
            | Error::Authorization
            | Error::DeviceNotFound
            | Error::DpsNotSupportedInNestedMode
            | Error::ModuleNotFound => None,
            Error::DpsClient(err) | Error::HubClient(err) | Error::KeyClient(err) => Some(err),
            Error::Internal(err) => Some(err),
            Error::InvalidParameter(_, err) => Some(&**err),
        }
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug)]
pub enum InternalError {
    BadSettings(std::io::Error),
    CreateCertificate(Box<dyn std::error::Error + Send + Sync>),
    CreateHomeDir(std::io::Error),
    GetModulePath(Box<dyn std::error::Error + Send + Sync>),
    InvalidProxyUri(Box<dyn std::error::Error + Send + Sync>),
    InvalidUri(http::uri::InvalidUri),
    LoadKeyOpensslEngine(openssl2::Error),
    LoadDeviceInfo(std::io::Error),
    LoadSettings(std::io::Error),
    MasterIdentityKey(std::io::Error),
    ParseDeviceInfo(toml::de::Error),
    ParseSettings(toml::de::Error),
    SaveDeviceInfo(std::io::Error),
    SaveModuleBackup(std::io::Error),
    SerializeDeviceInfo(toml::ser::Error),
    SaveSettings(std::io::Error),
}

impl std::fmt::Display for InternalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InternalError::BadSettings(m) => write!(f, "bad settings: {}", m),
            InternalError::CreateCertificate(_) => f.write_str("could not create certificate"),
            InternalError::CreateHomeDir(_) => f.write_str("could not create home directory"),
            InternalError::GetModulePath(_) => f.write_str("could not get module backup file path"),
            InternalError::InvalidProxyUri(_) => f.write_str("invalid proxy uri"),
            InternalError::InvalidUri(_) => f.write_str("invalid resource uri"),
            InternalError::LoadKeyOpensslEngine(_) => {
                f.write_str("could not load aziot-key-openssl-engine")
            }
            InternalError::LoadDeviceInfo(_) => {
                f.write_str("could not load device information state")
            }
            InternalError::LoadSettings(_) => f.write_str("could not load settings"),
            InternalError::MasterIdentityKey(_) => f.write_str("master identity key error"),
            InternalError::ParseDeviceInfo(_) => {
                f.write_str("could not parse device information state")
            }
            InternalError::ParseSettings(_) => f.write_str("could not parse settings"),
            InternalError::SaveDeviceInfo(_) => {
                f.write_str("could not save device information state")
            }
            InternalError::SaveModuleBackup(m) => {
                write!(f, "could not save module information backup state: {}", m)
            }
            InternalError::SerializeDeviceInfo(_) => {
                f.write_str("could not serialize device information state")
            }
            InternalError::SaveSettings(_) => f.write_str("could not save settings"),
        }
    }
}

impl std::error::Error for InternalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            InternalError::BadSettings(err) => Some(err),
            InternalError::CreateCertificate(err) => Some(&**err),
            InternalError::CreateHomeDir(err) => Some(err),
            InternalError::GetModulePath(err) => Some(&**err),
            InternalError::InvalidProxyUri(err) => Some(&**err),
            InternalError::InvalidUri(err) => Some(err),
            InternalError::LoadKeyOpensslEngine(err) => Some(err),
            InternalError::LoadDeviceInfo(err) => Some(err),
            InternalError::LoadSettings(err) => Some(err),
            InternalError::MasterIdentityKey(err) => Some(err),
            InternalError::ParseDeviceInfo(err) => Some(err),
            InternalError::ParseSettings(err) => Some(err),
            InternalError::SaveDeviceInfo(err) => Some(err),
            InternalError::SaveModuleBackup(err) => Some(err),
            InternalError::SaveSettings(err) => Some(err),
            InternalError::SerializeDeviceInfo(err) => Some(err),
        }
    }
}
