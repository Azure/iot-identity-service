// Copyright (c) Microsoft. All rights reserved.

#[derive(Debug)]
pub enum Error {
    Internal(InternalError),
    InvalidParameter(Option<(&'static str, Box<dyn std::error::Error + Send + Sync>)>),
}

impl Error {
    pub(crate) fn invalid_parameter<E>(name: &'static str, err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Error::InvalidParameter(Some((name, err.into())))
    }
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
    CreateKeyIfNotExistsGenerate(crate::keys::CreateKeyIfNotExistsError),
    CreateKeyIfNotExistsImport(crate::keys::ImportKeyError),
    CreateKeyPairIfNotExists(crate::keys::CreateKeyPairIfNotExistsError),
    GetKeyPairPublicParameter(crate::keys::GetKeyPairPublicParameterError),
    Decrypt(crate::keys::DecryptError),
    DeriveKey(crate::keys::DeriveKeyError),
    Encrypt(crate::keys::EncryptError),
    GenerateNonce(openssl::error::ErrorStack),
    LoadKey(crate::keys::LoadKeyError),
    LoadKeyPair(crate::keys::LoadKeyPairError),
    LoadLibrary(crate::keys::LoadLibraryError),
    ReadConfig(Box<dyn std::error::Error + Send + Sync>),
    SetLibraryParameter(crate::keys::SetLibraryParameterError),
    Sign(crate::keys::SignError),
    Verify(crate::keys::VerifyError),
}

impl std::fmt::Display for InternalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InternalError::CreateKeyIfNotExistsGenerate(_) => f.write_str("could not generate key"),
            InternalError::CreateKeyIfNotExistsImport(_) => f.write_str("could not import key"),
            InternalError::CreateKeyPairIfNotExists(_) => f.write_str("could not create key pair"),
            InternalError::Decrypt(_) => f.write_str("could not decrypt"),
            InternalError::DeriveKey(_) => f.write_str("could not derive key"),
            InternalError::Encrypt(_) => f.write_str("could not encrypt"),
            InternalError::GetKeyPairPublicParameter(_) => {
                f.write_str("could not get key pair parameter")
            }
            InternalError::GenerateNonce(_) => f.write_str("could not generate nonce"),
            InternalError::LoadKey(_) => f.write_str("could not load key"),
            InternalError::LoadKeyPair(_) => f.write_str("could not load key pair"),
            InternalError::LoadLibrary(_) => f.write_str("could not load libaziot-keys"),
            InternalError::ReadConfig(_) => f.write_str("could not read config"),
            InternalError::SetLibraryParameter(_) => {
                f.write_str("could not set parameter on libaziot-keys")
            }
            InternalError::Sign(_) => f.write_str("could not sign"),
            InternalError::Verify(_) => f.write_str("could not verify"),
        }
    }
}

impl std::error::Error for InternalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            InternalError::CreateKeyIfNotExistsGenerate(err) => Some(err),
            InternalError::CreateKeyIfNotExistsImport(err) => Some(err),
            InternalError::CreateKeyPairIfNotExists(err) => Some(err),
            InternalError::Decrypt(err) => Some(err),
            InternalError::DeriveKey(err) => Some(err),
            InternalError::Encrypt(err) => Some(err),
            InternalError::GetKeyPairPublicParameter(err) => Some(err),
            InternalError::GenerateNonce(err) => Some(err),
            InternalError::LoadKey(err) => Some(err),
            InternalError::LoadKeyPair(err) => Some(err),
            InternalError::LoadLibrary(err) => Some(err),
            InternalError::ReadConfig(err) => Some(&**err),
            InternalError::SetLibraryParameter(err) => Some(err),
            InternalError::Sign(err) => Some(err),
            InternalError::Verify(err) => Some(err),
        }
    }
}

impl From<crate::keys::LoadLibraryError> for Error {
    fn from(err: crate::keys::LoadLibraryError) -> Self {
        Error::Internal(InternalError::LoadLibrary(err))
    }
}

impl From<crate::keys::SetLibraryParameterError> for Error {
    fn from(err: crate::keys::SetLibraryParameterError) -> Self {
        Error::Internal(InternalError::SetLibraryParameter(err))
    }
}

impl From<crate::keys::CreateKeyPairIfNotExistsError> for Error {
    fn from(err: crate::keys::CreateKeyPairIfNotExistsError) -> Self {
        match err.err.0 {
            crate::keys::sys::AZIOT_KEYS_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
            _ => Error::Internal(InternalError::CreateKeyPairIfNotExists(err)),
        }
    }
}

impl From<crate::keys::LoadKeyPairError> for Error {
    fn from(err: crate::keys::LoadKeyPairError) -> Self {
        match err.err.0 {
            crate::keys::sys::AZIOT_KEYS_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
            _ => Error::Internal(InternalError::LoadKeyPair(err)),
        }
    }
}

impl From<crate::keys::GetKeyPairPublicParameterError> for Error {
    fn from(err: crate::keys::GetKeyPairPublicParameterError) -> Self {
        match err {
            crate::keys::GetKeyPairPublicParameterError::Api {
                err: crate::keys::KeysRawError(crate::keys::sys::AZIOT_KEYS_ERROR_INVALID_PARAMETER),
            } => Error::InvalidParameter(None),

            _ => Error::Internal(InternalError::GetKeyPairPublicParameter(err)),
        }
    }
}

impl From<crate::keys::CreateKeyIfNotExistsError> for Error {
    fn from(err: crate::keys::CreateKeyIfNotExistsError) -> Self {
        match err.err.0 {
            crate::keys::sys::AZIOT_KEYS_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
            _ => Error::Internal(InternalError::CreateKeyIfNotExistsGenerate(err)),
        }
    }
}

impl From<crate::keys::LoadKeyError> for Error {
    fn from(err: crate::keys::LoadKeyError) -> Self {
        match err.err.0 {
            crate::keys::sys::AZIOT_KEYS_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
            _ => Error::Internal(InternalError::LoadKey(err)),
        }
    }
}

impl From<crate::keys::ImportKeyError> for Error {
    fn from(err: crate::keys::ImportKeyError) -> Self {
        match err.err.0 {
            crate::keys::sys::AZIOT_KEYS_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
            _ => Error::Internal(InternalError::CreateKeyIfNotExistsImport(err)),
        }
    }
}

impl From<crate::keys::DeriveKeyError> for Error {
    fn from(err: crate::keys::DeriveKeyError) -> Self {
        match err.err.0 {
            crate::keys::sys::AZIOT_KEYS_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
            _ => Error::Internal(InternalError::DeriveKey(err)),
        }
    }
}

impl From<crate::keys::SignError> for Error {
    fn from(err: crate::keys::SignError) -> Self {
        match err.err.0 {
            crate::keys::sys::AZIOT_KEYS_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
            _ => Error::Internal(InternalError::Sign(err)),
        }
    }
}

impl From<crate::keys::VerifyError> for Error {
    fn from(err: crate::keys::VerifyError) -> Self {
        match err.err.0 {
            crate::keys::sys::AZIOT_KEYS_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
            _ => Error::Internal(InternalError::Verify(err)),
        }
    }
}

impl From<crate::keys::EncryptError> for Error {
    fn from(err: crate::keys::EncryptError) -> Self {
        match err.err.0 {
            crate::keys::sys::AZIOT_KEYS_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
            _ => Error::Internal(InternalError::Encrypt(err)),
        }
    }
}

impl From<crate::keys::DecryptError> for Error {
    fn from(err: crate::keys::DecryptError) -> Self {
        match err.err.0 {
            crate::keys::sys::AZIOT_KEYS_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
            _ => Error::Internal(InternalError::Decrypt(err)),
        }
    }
}
