#[derive(Debug)]
pub(crate) struct CertGenRawError(sys::CERTGEN_ERROR);

impl std::fmt::Display for CertGenRawError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self.0 {
			sys::CERTGEN_ERROR_FATAL => f.write_str("CERTGEN_ERROR_FATAL"),
			sys::CERTGEN_ERROR_INVALID_PARAMETER => f.write_str("CERTGEN_ERROR_INVALID_PARAMETER"),
			sys::CERTGEN_ERROR_EXTERNAL => f.write_str("CERTGEN_ERROR_EXTERNAL"),
			err => write!(f, "0x{:08x}", err),
		}
	}
}

#[derive(Debug)]
pub(crate) enum CertGen {
	V2_0_0_0 {
		set_parameter: unsafe extern "C" fn(
			name: *const std::os::raw::c_char,
			value: *const std::os::raw::c_char,
		) -> sys::CERTGEN_ERROR,

		create_or_load_cert: unsafe extern "C" fn(
			kind: sys::CERTGEN_CERT_KIND,
			uri: *const std::os::raw::c_char,
			public_key: *mut openssl_sys::EVP_PKEY,
			private_key: *mut openssl_sys::EVP_PKEY,
			pcert: *mut *mut openssl_sys::X509,
		) -> sys::CERTGEN_ERROR,

		import_cert: unsafe extern "C" fn(
			kind: sys::CERTGEN_CERT_KIND,
			uri: *const std::os::raw::c_char,
			cert: *mut openssl_sys::X509,
		) -> sys::CERTGEN_ERROR,

		delete_cert: unsafe extern "C" fn(
			kind: sys::CERTGEN_CERT_KIND,
			uri: *const std::os::raw::c_char,
		) -> sys::CERTGEN_ERROR,
	},
}

impl CertGen {
	pub(crate) fn new() -> Result<std::sync::Mutex<Self>, LoadCertGenError> {
		unsafe {
			let mut function_list: *const sys::CERTGEN_FUNCTION_LIST = std::ptr::null_mut();
			certgen_fn(|| sys::CERTGEN_get_function_list(&mut function_list)).map_err(LoadCertGenError::GetFunctionList)?;

			let api_version = (*function_list).version;
			let result = match api_version {
				sys::CERTGEN_VERSION_2_0_0_0 => {
					let function_list: *const sys::CERTGEN_FUNCTION_LIST_2_0_0_0 = function_list as _;

					CertGen::V2_0_0_0 {
						set_parameter: (*function_list).set_parameter.ok_or(LoadCertGenError::MissingFunction("set_parameter"))?,
						create_or_load_cert: (*function_list).create_or_load_cert.ok_or(LoadCertGenError::MissingFunction("create_or_load_cert"))?,
						import_cert: (*function_list).import_cert.ok_or(LoadCertGenError::MissingFunction("import_cert"))?,
						delete_cert: (*function_list).delete_cert.ok_or(LoadCertGenError::MissingFunction("delete_cert"))?,
					}
				},

				api_version => return Err(LoadCertGenError::UnsupportedApiVersion(api_version)),
			};

			println!("Loaded certgen library with version 0x{:08x}, {:?}", api_version, result);

			Ok(std::sync::Mutex::new(result))
		}
	}
}

#[derive(Debug)]
pub(crate) enum LoadCertGenError {
	GetFunctionList(CertGenRawError),
	MissingFunction(&'static str),
	UnsupportedApiVersion(sys::CERTGEN_VERSION),
}

impl std::fmt::Display for LoadCertGenError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			LoadCertGenError::GetFunctionList(inner) => write!(f, "could not get function list: {}", inner),
			LoadCertGenError::MissingFunction(name) => write!(f, "library does not define {}", name),
			LoadCertGenError::UnsupportedApiVersion(api_version) => write!(f, "library exports API version 0x{:08x} which is not supported", api_version),
		}
	}
}

impl std::error::Error for LoadCertGenError {
}

impl CertGen {
	pub(crate) fn set_parameter(&mut self, name: &std::ffi::CStr, value: &std::ffi::CStr) -> Result<(), SetCertGenParameterError> {
		unsafe {
			match self {
				CertGen::V2_0_0_0 { set_parameter, .. } => {
					certgen_fn(|| set_parameter(
						name.as_ptr(),
						value.as_ptr(),
					)).map_err(|err| SetCertGenParameterError { name: name.to_string_lossy().into_owned(), err })?;

					Ok(())
				},
			}
		}
	}
}

#[derive(Debug)]
pub(crate) struct SetCertGenParameterError {
	name: String,
	err: CertGenRawError,
}

impl std::fmt::Display for SetCertGenParameterError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "could not set {} parameter on library: {}", self.name, self.err)
	}
}

impl std::error::Error for SetCertGenParameterError {
}

impl CertGen {
	pub(crate) fn create_or_load_cert(
		&mut self,
		kind: CertKind,
		uri: Option<&std::ffi::CStr>,
		public_key: &openssl::pkey::PKeyRef<openssl::pkey::Public>,
		private_key: &openssl::pkey::PKeyRef<openssl::pkey::Private>,
	) -> Result<openssl::x509::X509, CreateOrLoadCertError> {
		unsafe {
			match self {
				CertGen::V2_0_0_0 { create_or_load_cert, .. } => {
					let mut cert: *mut openssl_sys::X509 = std::ptr::null_mut();
					certgen_fn(|| create_or_load_cert(
						kind.into(),
						uri.map(std::ffi::CStr::as_ptr).unwrap_or(std::ptr::null()),
						foreign_types_shared::ForeignTypeRef::as_ptr(public_key),
						foreign_types_shared::ForeignTypeRef::as_ptr(private_key),
						&mut cert,
					)).map_err(|err| CreateOrLoadCertError::Api { err })?;

					let mut cert = std::ptr::NonNull::new(cert).ok_or(CreateOrLoadCertError::NullCert)?;

					Ok(foreign_types_shared::ForeignType::from_ptr(cert.as_mut()))
				},
			}
		}
	}
}

#[derive(Debug)]
pub(crate) enum CreateOrLoadCertError {
	Api { err: CertGenRawError },
	NullCert,
}

impl std::fmt::Display for CreateOrLoadCertError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			CreateOrLoadCertError::Api { err } => write!(f, "could not create or load cert: {}", err),
			CreateOrLoadCertError::NullCert => f.write_str("could not create or load cert: create_or_load_cert succeeded but cert is NULL"),
		}
	}
}

impl std::error::Error for CreateOrLoadCertError {
}

impl CertGen {
	pub(crate) fn import_cert(
		&mut self,
		kind: CertKind,
		uri: Option<&std::ffi::CStr>,
		cert: &openssl::x509::X509Ref,
	) -> Result<(), ImportCertError> {
		unsafe {
			match self {
				CertGen::V2_0_0_0 { import_cert, .. } => {
					certgen_fn(|| import_cert(
						kind.into(),
						uri.map(std::ffi::CStr::as_ptr).unwrap_or(std::ptr::null()),
						foreign_types_shared::ForeignTypeRef::as_ptr(cert),
					)).map_err(|err| ImportCertError { err })?;

					Ok(())
				},
			}
		}
	}
}

#[derive(Debug)]
pub(crate) struct ImportCertError {
	err: CertGenRawError,
}

impl std::fmt::Display for ImportCertError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "could not import cert: {}", self.err)
	}
}

impl std::error::Error for ImportCertError {
}

impl CertGen {
	pub(crate) fn delete_cert(
		&mut self,
		kind: CertKind,
		uri: Option<&std::ffi::CStr>,
	) -> Result<(), DeleteCertError> {
		unsafe {
			match self {
				CertGen::V2_0_0_0 { delete_cert, .. } => {
					certgen_fn(|| delete_cert(
						kind.into(),
						uri.map(std::ffi::CStr::as_ptr).unwrap_or(std::ptr::null()),
					)).map_err(|err| DeleteCertError { err })?;

					Ok(())
				},
			}
		}
	}
}

#[derive(Debug)]
pub(crate) struct DeleteCertError {
	err: CertGenRawError,
}

impl std::fmt::Display for DeleteCertError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "could not delete cert: {}", self.err)
	}
}

impl std::error::Error for DeleteCertError {
}

#[allow(unused)] // TODO: Remove
#[derive(Debug, Clone, Copy)]
pub(crate) enum CertKind {
	DeviceId,
	DeviceCa,
	WorkloadCa,
	ModuleServer,
}

impl Into<sys::CERTGEN_CERT_KIND> for CertKind {
	fn into(self) -> sys::CERTGEN_CERT_KIND {
		let result = match self {
			CertKind::DeviceId => sys::CERTGEN_CERT_KIND_DEVICE_ID,
			CertKind::DeviceCa => sys::CERTGEN_CERT_KIND_DEVICE_CA,
			CertKind::WorkloadCa => sys::CERTGEN_CERT_KIND_WORKLOAD_CA,
			CertKind::ModuleServer => sys::CERTGEN_CERT_KIND_MODULE_SERVER,
		};

		// CERTGEN_CERT_KIND is a u8, but cbindgen emits them as #define'd untyped numeric constants,
		// and bindgen then emits untyped numeric constants are u32. So we need to cast them.
		std::convert::TryInto::try_into(result).expect("u32 -> u8")
	}
}

fn certgen_fn(f: impl FnOnce() -> sys::CERTGEN_ERROR) -> Result<(), CertGenRawError> {
	match f() {
		sys::CERTGEN_SUCCESS => Ok(()),
		err => Err(CertGenRawError(err)),
	}
}

mod sys {
	#![allow(
		non_camel_case_types,
		non_snake_case,
		unused,
		clippy::unreadable_literal,
	)]

	use openssl_sys::{ EVP_PKEY, X509 };

	include!("certgen.generated.rs");
}
