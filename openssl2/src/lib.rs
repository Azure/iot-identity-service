// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::default_trait_access,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::use_self
)]

/// Error type for openssl engine operations.
#[derive(Debug)]
pub enum Error {
    SysReturnedNull {
        inner: openssl::error::ErrorStack,
    },
    SysReturnedUnexpected {
        expected: std::os::raw::c_int,
        actual: std::os::raw::c_int,
        inner: openssl::error::ErrorStack,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::SysReturnedNull { .. } => write!(
                f,
                "expected operation to return valid pointer but it returned NULL"
            ),
            Error::SysReturnedUnexpected {
                expected, actual, ..
            } => write!(
                f,
                "expected operation to return {} but it returned {}",
                expected, actual
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[allow(clippy::match_same_arms)]
        match self {
            Error::SysReturnedNull { inner } => Some(inner),
            Error::SysReturnedUnexpected { inner, .. } => Some(inner),
        }
    }
}

foreign_types::foreign_type! {
    type CType = openssl_sys::ENGINE;

    fn drop = |ptr| { let _ = openssl_sys2::ENGINE_free(ptr); };

    /// A "structural reference" to an openssl engine.
    pub struct StructuralEngine;

    /// Reference to [`StructualEngine`]
    pub struct StructuralEngineRef;
}

impl StructuralEngine {
    /// Loads an engine by its ID.
    pub fn by_id(id: &std::ffi::CStr) -> Result<Self, Error> {
        unsafe {
            let ptr = openssl_returns_nonnull(openssl_sys2::ENGINE_by_id(id.as_ptr()))?;
            Ok(foreign_types_shared::ForeignType::from_ptr(ptr))
        }
    }
}

foreign_types::foreign_type! {
    type CType = openssl_sys::ENGINE;

    fn drop = |ptr| { let _ = openssl_sys2::ENGINE_finish(ptr); };

    /// A "functional reference" to an openssl engine.
    ///
    /// Can be obtained by using [`std::convert::TryInto::try_into`] on a [`StructuralEngine`]
    pub struct FunctionalEngine;

    /// Reference to [`StructualEngine`]
    pub struct FunctionalEngineRef;
}

impl std::fmt::Debug for FunctionalEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionalEngine").finish()
    }
}

// openssl engines don't have thread affinity
unsafe impl Send for FunctionalEngine {}

impl FunctionalEngineRef {
    /// Queries the engine for its name.
    pub fn name(&self) -> Result<&std::ffi::CStr, Error> {
        unsafe {
            let this = foreign_types_shared::ForeignTypeRef::as_ptr(self);
            let name = openssl_returns_nonnull_const(openssl_sys2::ENGINE_get_name(this))?;
            let name = std::ffi::CStr::from_ptr(name);
            Ok(name)
        }
    }

    /// Loads the public key with the given ID.
    pub fn load_public_key(
        &mut self,
        id: &std::ffi::CStr,
    ) -> Result<openssl::pkey::PKey<openssl::pkey::Public>, Error> {
        unsafe {
            let this = foreign_types_shared::ForeignTypeRef::as_ptr(self);
            let result = openssl_returns_nonnull(openssl_sys2::ENGINE_load_public_key(
                this,
                id.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ))?;
            let result = foreign_types_shared::ForeignType::from_ptr(result);
            Ok(result)
        }
    }

    /// Loads the private key with the given ID.
    pub fn load_private_key(
        &mut self,
        id: &std::ffi::CStr,
    ) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, Error> {
        unsafe {
            let this = foreign_types_shared::ForeignTypeRef::as_ptr(self);
            let result = openssl_returns_nonnull(openssl_sys2::ENGINE_load_private_key(
                this,
                id.as_ptr(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ))?;
            let result = foreign_types_shared::ForeignType::from_ptr(result);
            Ok(result)
        }
    }
}

impl std::convert::TryFrom<StructuralEngine> for FunctionalEngine {
    type Error = Error;

    fn try_from(engine: StructuralEngine) -> Result<Self, Self::Error> {
        unsafe {
            let ptr = foreign_type_into_ptr(engine);

            openssl_returns_1(openssl_sys2::ENGINE_init(ptr))?;

            Ok(foreign_types_shared::ForeignType::from_ptr(ptr))
        }
    }
}

/// Returns an error if the argument isn't positive.
pub fn openssl_returns_positive(result: std::os::raw::c_int) -> Result<(), Error> {
    if result > 0 {
        Ok(())
    } else {
        Err(Error::SysReturnedUnexpected {
            expected: 1,
            actual: result,
            inner: openssl::error::ErrorStack::get(),
        })
    }
}

/// Returns an error if the argument isn't `1`.
pub fn openssl_returns_1(result: std::os::raw::c_int) -> Result<(), Error> {
    if result == 1 {
        Ok(())
    } else {
        Err(Error::SysReturnedUnexpected {
            expected: 1,
            actual: result,
            inner: openssl::error::ErrorStack::get(),
        })
    }
}

/// Returns an error if the argument is nullptr.
pub fn openssl_returns_nonnull<T>(result: *mut T) -> Result<*mut T, Error> {
    if result.is_null() {
        Err(Error::SysReturnedNull {
            inner: openssl::error::ErrorStack::get(),
        })
    } else {
        Ok(result)
    }
}

/// Returns an error if the argument is nullptr.
pub fn openssl_returns_nonnull_const<T>(result: *const T) -> Result<*const T, Error> {
    if result.is_null() {
        Err(Error::SysReturnedNull {
            inner: openssl::error::ErrorStack::get(),
        })
    } else {
        Ok(result)
    }
}

/// Convert an `ForeignType` value into its owned `CType` pointer.
///
/// This was added in foreign-types-shared 0.3, but openssl still uses 0.1, so reimplement it here.
pub fn foreign_type_into_ptr<T>(value: T) -> *mut <T as foreign_types_shared::ForeignType>::CType
where
    T: foreign_types_shared::ForeignType,
{
    // Every ForeignType is a wrapper around a pointer. So destroying its storage will still leave us with a valid pointer.
    let result = value.as_ptr();
    std::mem::forget(value);
    result
}

/// This trait defines the getter and setter for this type's ex data.
pub trait ExDataAccessors {
    const GET_FN: unsafe extern "C" fn(
        this: *const Self,
        idx: std::os::raw::c_int,
    ) -> *mut std::ffi::c_void;
    const SET_FN: unsafe extern "C" fn(
        this: *mut Self,
        idx: std::os::raw::c_int,
        arg: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int;
}

#[cfg(ossl110)]
impl ExDataAccessors for openssl_sys::EC_KEY {
    const GET_FN: unsafe extern "C" fn(
        this: *const Self,
        idx: std::os::raw::c_int,
    ) -> *mut std::ffi::c_void = openssl_sys2::EC_KEY_get_ex_data;
    const SET_FN: unsafe extern "C" fn(
        this: *mut Self,
        idx: std::os::raw::c_int,
        arg: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int = openssl_sys2::EC_KEY_set_ex_data;
}

#[cfg(not(ossl110))]
impl ExDataAccessors for openssl_sys::EC_KEY {
    const GET_FN: unsafe extern "C" fn(
        this: *const Self,
        idx: std::os::raw::c_int,
    ) -> *mut std::ffi::c_void = openssl_sys2::ECDSA_get_ex_data;
    const SET_FN: unsafe extern "C" fn(
        this: *mut Self,
        idx: std::os::raw::c_int,
        arg: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int = openssl_sys2::ECDSA_set_ex_data;
}

impl ExDataAccessors for openssl_sys::ENGINE {
    const GET_FN: unsafe extern "C" fn(
        this: *const Self,
        idx: std::os::raw::c_int,
    ) -> *mut std::ffi::c_void = openssl_sys2::ENGINE_get_ex_data;
    const SET_FN: unsafe extern "C" fn(
        this: *mut Self,
        idx: std::os::raw::c_int,
        arg: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int = openssl_sys2::ENGINE_set_ex_data;
}

impl ExDataAccessors for openssl_sys::RSA {
    const GET_FN: unsafe extern "C" fn(
        this: *const Self,
        idx: std::os::raw::c_int,
    ) -> *mut std::ffi::c_void = openssl_sys2::RSA_get_ex_data;
    const SET_FN: unsafe extern "C" fn(
        this: *mut Self,
        idx: std::os::raw::c_int,
        arg: *mut std::ffi::c_void,
    ) -> std::os::raw::c_int = openssl_sys2::RSA_set_ex_data;
}

/// The kinds of EC curves supported for key generation.
#[cfg_attr(not(ossl111), allow(clippy::pub_enum_variant_names))] // "All variants start with Nist"
#[derive(Clone, Copy, Debug)]
pub enum EcCurve {
    /// ed25519
    ///
    /// Note: Requires openssl >= 1.1.1
    ///
    /// Note: This has not been tested since softhsm does not support it, which in turn is because openssl (as of v1.1.1c) does not support it
    /// for key generation.
    #[cfg(ossl111)]
    Ed25519,

    /// secp256r1, known to openssl as prime256v1
    NistP256,

    /// secp384r1
    NistP384,

    /// secp521r1
    NistP521,
}

impl EcCurve {
    #[cfg(ossl111)]
    const ED25519_OID_DER: &'static [u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
    const SECP256R1_OID_DER: &'static [u8] =
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    const SECP384R1_OID_DER: &'static [u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
    const SECP521R1_OID_DER: &'static [u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

    pub fn as_nid(self) -> openssl::nid::Nid {
        match self {
            #[cfg(ossl111)]
            EcCurve::Ed25519 => openssl::nid::Nid::from_raw(openssl_sys::NID_ED25519), // Not wrapped by openssl as of v0.10.25
            EcCurve::NistP256 => openssl::nid::Nid::X9_62_PRIME256V1,
            EcCurve::NistP384 => openssl::nid::Nid::SECP384R1,
            EcCurve::NistP521 => openssl::nid::Nid::SECP521R1,
        }
    }

    pub fn as_oid_der(self) -> &'static [u8] {
        match self {
            #[cfg(ossl111)]
            EcCurve::Ed25519 => EcCurve::ED25519_OID_DER,
            EcCurve::NistP256 => EcCurve::SECP256R1_OID_DER,
            EcCurve::NistP384 => EcCurve::SECP384R1_OID_DER,
            EcCurve::NistP521 => EcCurve::SECP521R1_OID_DER,
        }
    }

    pub fn from_nid(nid: openssl::nid::Nid) -> Option<Self> {
        match nid {
            #[cfg(ossl111)]
            nid if nid.as_raw() == openssl_sys::NID_ED25519 => Some(EcCurve::Ed25519),
            openssl::nid::Nid::X9_62_PRIME256V1 => Some(EcCurve::NistP256),
            openssl::nid::Nid::SECP384R1 => Some(EcCurve::NistP384),
            openssl::nid::Nid::SECP521R1 => Some(EcCurve::NistP521),
            _ => None,
        }
    }

    pub fn from_oid_der(oid: &[u8]) -> Option<Self> {
        match oid {
            #[cfg(ossl111)]
            EcCurve::ED25519_OID_DER => Some(EcCurve::Ed25519),
            EcCurve::SECP256R1_OID_DER => Some(EcCurve::NistP256),
            EcCurve::SECP384R1_OID_DER => Some(EcCurve::NistP384),
            EcCurve::SECP521R1_OID_DER => Some(EcCurve::NistP521),
            _ => None,
        }
    }
}
