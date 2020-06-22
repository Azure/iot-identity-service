#[derive(Debug)]
pub enum Error {
	Internal(InternalError),
	InvalidParameter(Option<(&'static str, Box<dyn std::error::Error + Send + Sync>)>),
}

impl Error {
	pub(crate) fn invalid_parameter<E>(name: &'static str, err: E) -> Self where E: Into<Box<dyn std::error::Error + Send + Sync>> {
		Error::InvalidParameter(Some((name, err.into())))
	}
}

impl std::fmt::Display for Error {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Error::Internal(_) => f.write_str("internal error"),
			Error::InvalidParameter(Some((name, _))) => write!(f, "parameter {:?} has an invalid value", name),
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

#[derive(Debug)]
pub enum InternalError {
	CreateKeyIfNotExistsGenerate(crate::keygen::CreateKeyIfNotExistsError),
	CreateKeyIfNotExistsImport(crate::keygen::ImportKeyError),
	CreateKeyPairIfNotExists(crate::keygen::CreateKeyPairIfNotExistsError),
	GetKeyPairPublicParameter(crate::keygen::GetKeyPairPublicParameterError),
	Decrypt(crate::keygen::DecryptError),
	Encrypt(crate::keygen::EncryptError),
	GenerateNonce(openssl::error::ErrorStack),
	LoadKeyPair(crate::keygen::LoadKeyPairError),
	LoadLibrary(crate::keygen::LoadLibraryError),
	SetLibraryParameter(crate::keygen::SetLibraryParameterError),
	Sign(crate::keygen::SignError),
	Verify(crate::keygen::VerifyError),
}

impl std::fmt::Display for InternalError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			InternalError::CreateKeyIfNotExistsGenerate(_) => f.write_str("could not generate key"),
			InternalError::CreateKeyIfNotExistsImport(_) => f.write_str("could not import key"),
			InternalError::CreateKeyPairIfNotExists(_) => f.write_str("could not create key pair"),
			InternalError::Decrypt(_) => f.write_str("could not decrypt"),
			InternalError::Encrypt(_) => f.write_str("could not encrypt"),
			InternalError::GetKeyPairPublicParameter(_) => f.write_str("could not get key pair parameter"),
			InternalError::GenerateNonce(_) => f.write_str("could not generate nonce"),
			InternalError::LoadKeyPair(_) => f.write_str("could not load key pair"),
			InternalError::LoadLibrary(_) => f.write_str("could not load keygen library"),
			InternalError::SetLibraryParameter(_) => f.write_str("could not set parameter on keygen library"),
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
			InternalError::Encrypt(err) => Some(err),
			InternalError::GetKeyPairPublicParameter(err) => Some(err),
			InternalError::GenerateNonce(err) => Some(err),
			InternalError::LoadKeyPair(err) => Some(err),
			InternalError::LoadLibrary(err) => Some(err),
			InternalError::SetLibraryParameter(err) => Some(err),
			InternalError::Sign(err) => Some(err),
			InternalError::Verify(err) => Some(err),
		}
	}
}

impl From<crate::keygen::LoadLibraryError> for Error {
	fn from(err: crate::keygen::LoadLibraryError) -> Self {
		Error::Internal(InternalError::LoadLibrary(err))
	}
}

impl From<crate::keygen::SetLibraryParameterError> for Error {
	fn from(err: crate::keygen::SetLibraryParameterError) -> Self {
		Error::Internal(InternalError::SetLibraryParameter(err))
	}
}

impl From<crate::keygen::CreateKeyPairIfNotExistsError> for Error {
	fn from(err: crate::keygen::CreateKeyPairIfNotExistsError) -> Self {
		match err.err.0 {
			crate::keygen::sys::KEYGEN_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
			_ => Error::Internal(InternalError::CreateKeyPairIfNotExists(err)),
		}
	}
}

impl From<crate::keygen::LoadKeyPairError> for Error {
	fn from(err: crate::keygen::LoadKeyPairError) -> Self {
		match err.err.0 {
			crate::keygen::sys::KEYGEN_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
			_ => Error::Internal(InternalError::LoadKeyPair(err)),
		}
	}
}

impl From<crate::keygen::GetKeyPairPublicParameterError> for Error {
	fn from(err: crate::keygen::GetKeyPairPublicParameterError) -> Self {
		match err {
			crate::keygen::GetKeyPairPublicParameterError::Api {
				err: crate::keygen::KeyGenRawError(crate::keygen::sys::KEYGEN_ERROR_INVALID_PARAMETER),
			} =>
				Error::InvalidParameter(None),

			_ => Error::Internal(InternalError::GetKeyPairPublicParameter(err)),
		}
	}
}

impl From<crate::keygen::CreateKeyIfNotExistsError> for Error {
	fn from(err: crate::keygen::CreateKeyIfNotExistsError) -> Self {
		match err.err.0 {
			crate::keygen::sys::KEYGEN_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
			_ => Error::Internal(InternalError::CreateKeyIfNotExistsGenerate(err)),
		}
	}
}

impl From<crate::keygen::ImportKeyError> for Error {
	fn from(err: crate::keygen::ImportKeyError) -> Self {
		match err.err.0 {
			crate::keygen::sys::KEYGEN_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
			_ => Error::Internal(InternalError::CreateKeyIfNotExistsImport(err)),
		}
	}
}

impl From<crate::keygen::SignError> for Error {
	fn from(err: crate::keygen::SignError) -> Self {
		match err.err.0 {
			crate::keygen::sys::KEYGEN_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
			_ => Error::Internal(InternalError::Sign(err)),
		}
	}
}

impl From<crate::keygen::VerifyError> for Error {
	fn from(err: crate::keygen::VerifyError) -> Self {
		match err.err.0 {
			crate::keygen::sys::KEYGEN_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
			_ => Error::Internal(InternalError::Verify(err)),
		}
	}
}

impl From<crate::keygen::EncryptError> for Error {
	fn from(err: crate::keygen::EncryptError) -> Self {
		match err.err.0 {
			crate::keygen::sys::KEYGEN_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
			_ => Error::Internal(InternalError::Encrypt(err)),
		}
	}
}

impl From<crate::keygen::DecryptError> for Error {
	fn from(err: crate::keygen::DecryptError) -> Self {
		match err.err.0 {
			crate::keygen::sys::KEYGEN_ERROR_INVALID_PARAMETER => Error::InvalidParameter(None),
			_ => Error::Internal(InternalError::Decrypt(err)),
		}
	}
}
