#![deny(rust_2018_idioms, warnings)]
#![allow(
	non_camel_case_types,
	clippy::let_and_return,
	clippy::missing_safety_doc,
)]

//! This library is used to create and load certificates for the Azure IoT Edge daemon.
//!
//! While it is written in Rust, its interaction with the Azure IoT Edge daemon is over a C API. This is because this library can be swapped
//! with another implementation of your choice that exposes the same C API. The documentation of this library is aimed at both
//! readers looking to understand this particular implementation, as well as readers looking to implement their own certgen library.
//!
//!
//! # API conventions
//!
//! All functions return a `std::os::raw::c_uint` to indicate success or failure. See the [`CERTGEN_ERROR`] type's docs for details about these constants.
//!
//! The only function exported by a certgen library is [`CERTGEN_get_function_list`]. Call this function to get the version of the certgen API
//! that this library exports, as well as the function pointers to the certgen operations. See its docs for more details.
//!
//! All calls to [`CERTGEN_get_function_list`] or any function in [`CERTGEN_FUNCTION_LIST`] are serialized, ie a function will not be called
//! while another function is running. However, it is not guaranteed that all function calls will be made from the same operating system thread.
//! Thus, implementations do not need to worry about locking to prevent concurrent access, but should also not store data in thread-local storage.

// DEVNOTE:
//
// Keep the above header in sync with cbindgen.prelude.h


mod implementation;


// DEVNOTE:
//
// Transparent newtypes around integers must be specified as non-tuple structs. Eg `struct CERTGEN_ERROR { inner: u32 }`, not `struct CERTGEN_ERROR(u32)`.
// This is because cbindgen requires constants to be assigned with struct expressions like `CERTGEN_ERROR { inner: 0 }`,
// whereas `CERTGEN_ERROR(0)` is a call expression that makes cbindgen ignore the constant.


/// Error type. This is a transparent wrapper around a `std::os::raw::c_uint` (`unsigned int`).
///
/// Either `CERTGEN_SUCCESS` or one of the `CERTGEN_ERROR_*` constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct CERTGEN_ERROR { inner: std::os::raw::c_uint }

/// The operation succeeded.
pub const CERTGEN_SUCCESS: CERTGEN_ERROR = CERTGEN_ERROR { inner: 0 };

/// The library encountered an unrecoverable error. The process should exit as soon as possible.
pub const CERTGEN_ERROR_FATAL: CERTGEN_ERROR = CERTGEN_ERROR { inner: 1 };

/// The operation failed because a parameter has an invalid value.
pub const CERTGEN_ERROR_INVALID_PARAMETER: CERTGEN_ERROR = CERTGEN_ERROR { inner: 2 };

/// The library encountered an error with an external resource, such as an I/O error or RPC error.
pub const CERTGEN_ERROR_EXTERNAL: CERTGEN_ERROR = CERTGEN_ERROR { inner: 3 };


/// Represents the version of the certgen API exported by this library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct CERTGEN_VERSION { inner: std::os::raw::c_uint }

/// Version 2.0.0.0
pub const CERTGEN_VERSION_2_0_0_0: CERTGEN_VERSION = CERTGEN_VERSION { inner: 0x02_00_00_00 };


/// The kind of cert that is being requested.
///
/// One of the `CERTGEN_CERT_KIND_*` constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct CERTGEN_CERT_KIND { inner: std::os::raw::c_uint }

/// A device identity cert.
pub const CERTGEN_CERT_KIND_DEVICE_ID: CERTGEN_CERT_KIND = CERTGEN_CERT_KIND { inner: 1 };

/// A device CA cert.
pub const CERTGEN_CERT_KIND_DEVICE_CA: CERTGEN_CERT_KIND = CERTGEN_CERT_KIND { inner: 2 };

/// A workload CA cert.
pub const CERTGEN_CERT_KIND_WORKLOAD_CA: CERTGEN_CERT_KIND = CERTGEN_CERT_KIND { inner: 3 };

/// A module server cert.
pub const CERTGEN_CERT_KIND_MODULE_SERVER: CERTGEN_CERT_KIND = CERTGEN_CERT_KIND { inner: 4 };


/// The specific implementation of [`CERTGEN_FUNCTION_LIST`] for API version 2.0.0.0
#[derive(Debug)]
#[repr(C)]
pub struct CERTGEN_FUNCTION_LIST_2_0_0_0 {
	/// The version of the certgen API exported by this library.
	///
	/// For the `CERTGEN_FUNCTION_LIST_2_0_0_0` type, the value must be [`CERTGEN_VERSION_2_0_0_0`].
	pub version: CERTGEN_VERSION,

	/// Set a parameter on this library.
	///
	/// `name` must not be `NULL`.
	/// `value` may be `NULL`.
	///
	/// The caller may free the name string after this method returns. If the implementation needs to hold on to it, it must make a copy.
	///
	/// The interpretation of names and values depends on the implementation.
	///
	/// # Errors
	///
	/// - `CERTGEN_ERROR_INVALID_PARAMETER`:
	///   - `name` is `NULL`.
	///   - `name` is not recognized by this implementation.
	///   - `value` is invalid.
	///
	/// - `CERTGEN_ERROR_FATAL`
	pub set_parameter: unsafe extern "C" fn(
		name: *const std::os::raw::c_char,
		value: *const std::os::raw::c_char,
	) -> CERTGEN_ERROR,

	/// Create or load a cert of the specified `kind`.
	///
	/// - If `uri` is `NULL`:
	///   - If the implementation can generated a new signed cert (including the case where it decides to create a self-signed cert),
	///     it does so and saves at a location of the implementation's choice. It returns this cert in `pcert`.
	///   - Otherwise the implementation generates an unsigned cert. It returns this cert in `pcert`. The unsigned cert is not persisted anywhere.
	///
	/// - If `uri` is not `NULL` and a cert exists at that URI, the implementation returns the cert in `pcert`.
	///
	/// - If `uri` is not `NULL` and a cert does not exist at that URI:
	///   - If the implementation can generated a new signed cert (including the case where it decides to create a self-signed cert),
	///     it does so and saves it such that it can be looked up again later using that same URI. It returns this cert in `pcert`.
	///   - Otherwise the implementation generates an unsigned cert. It returns this cert in `pcert`. The unsigned cert is not persisted anywhere.
	///
	/// Note again that the implementation must not persist unsigned certs such that future calls to `create_or_load_key` return
	/// previously-created unsigned certs.
	///
	/// The interpretation of a URI depends on the implementation. This library understands `file` URIs.
	///
	/// In the case where the implementation needs to create a new cert, whether it can produce signed certificates or only unsigned ones depends on
	/// the implementation. This library only produces self-signed certs for the Device CA kind, and unsigned certs for all other kinds.
	///
	/// If the implementation returns an unsigned cert, it is the caller's job to sign it with a signer of its choice.
	/// The signed cert can be imported back into the certgen implementation using [`import`]. If the caller specified a URI for `create_or_load_cert`,
	/// it will almost certainly want to use the same URI for `import`, because it will need to use the URI given to `import` with `create_or_load_cert` later
	/// when it wants to load the cert again.
	///
	/// `public_key` and `private_key` are the keys to be used for creating a new cert. `private_key` would only get used if the implementation wants to make
	/// a self-signed cert, but it is still required.
	///
	/// # Errors
	///
	/// - `CERTGEN_ERROR_INVALID_PARAMETER`:
	///   - `kind` is not recognized by this implementation, or the implementation does not support generating certs of this kind.
	///   - `uri` is not recognized by this implementation, or is invalid in some other way.
	///   - `public_key` is `NULL`.
	///   - `private_key` is `NULL`.
	///   - `pcert` is `NULL`.
	pub create_or_load_cert: unsafe extern "C" fn(
		kind: CERTGEN_CERT_KIND,
		uri: *const std::os::raw::c_char,
		public_key: *mut openssl_sys::EVP_PKEY,
		private_key: *mut openssl_sys::EVP_PKEY,
		pcert: *mut *mut openssl_sys::X509,
	) -> CERTGEN_ERROR,

	/// Import a cert of the specified `kind`.
	///
	/// - If `uri` is `NULL`, then the cert will be saved at a location of the implementation's choice. This must be consistent with the choice
	///   made in [`create_or_load_cert`].
	/// - If `uri` is not `NULL`, the cert will be saved such that it can be looked up later using [`create_or_load_cert`] with that same URI.
	///   If a cert already exists at the URI, it is overwritten.
	///
	/// The interpretation of a URI depends on the implementation. This library understands `file` URIs.
	///
	/// # Errors
	///
	/// - `CERTGEN_ERROR_INVALID_PARAMETER`:
	///   - `kind` is not recognized by this implementation.
	///   - `uri` is not recognized by this implementation, or is invalid in some other way.
	///   - `cert` is `NULL`.
	pub import_cert: unsafe extern "C" fn(
		kind: CERTGEN_CERT_KIND,
		uri: *const std::os::raw::c_char,
		cert: *mut openssl_sys::X509,
	) -> CERTGEN_ERROR,

	/// Delete a cert of the specified `kind`.
	///
	/// If `uri` is `NULL`, then the cert's location will be determined by the implementation. This must be consistent with the choice
	/// made in [`create_or_load_cert`].
	///
	/// The interpretation of a URI depends on the implementation. This library understands `file` URIs.
	///
	/// # Errors
	///
	/// - `CERTGEN_ERROR_INVALID_PARAMETER`:
	///   - `kind` is not recognized by this implementation.
	///   - `uri` is not recognized by this implementation, or is invalid in some other way.
	pub delete_cert: unsafe extern "C" fn(
		kind: CERTGEN_CERT_KIND,
		uri: *const std::os::raw::c_char,
	) -> CERTGEN_ERROR,
}


/// The latest version of the certgen API defined in this header.
///
/// Returned by [`CERTGEN_get_function_list`]
pub type CERTGEN_FUNCTION_LIST = CERTGEN_FUNCTION_LIST_2_0_0_0;


/// Get the list of functions for certgen operations.
///
/// Implementations can use this function for initialization, since it is guaranteed to be called before any certgen operations.
/// However it is not an error to call this function multiple times, so implementations must ensure they only run their initialization once.
///
/// The pointer returned from this function must not be freed by the caller, and its contents must not be mutated.
#[no_mangle]
pub unsafe extern "C" fn CERTGEN_get_function_list(
	pfunction_list: *mut *const CERTGEN_FUNCTION_LIST,
) -> CERTGEN_ERROR {
	implementation::get_function_list(pfunction_list)
}


/// Catches the error, if any, and returns it. Otherwise returns [`CERTGEN_SUCCESS`].
fn r#catch(f: impl FnOnce() -> Result<(), CERTGEN_ERROR>) -> CERTGEN_ERROR {
	match f() {
		Ok(()) => CERTGEN_SUCCESS,
		Err(err) => err,
	}
}
