// Copyright (c) Microsoft. All rights reserved.

#![deny(rust_2018_idioms, warnings)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
	non_camel_case_types,
	clippy::default_trait_access,
	clippy::doc_markdown, // clippy wants "IoT" in a code fence
	clippy::let_and_return,
	clippy::let_unit_value,
	clippy::missing_safety_doc,
	clippy::shadow_unrelated,
	clippy::similar_names,
	clippy::too_many_lines,
	clippy::type_complexity,
)]

//! This library is used to create and load keys for the Azure IoT Keys Service.
//!
//! While it is written in Rust, its interaction with the Azure IoT Keys Services is via a C API. This is because this library can be swapped
//! with another implementation of your choice that exposes the same C API. The documentation of this library is aimed at both
//! readers looking to understand this particular implementation, as well as readers looking to implement their own libaziot-keys library.
//!
//!
//! # API conventions
//!
//! All functions return an `unsigned int` to indicate success or failure. See the [`AZIOT_KEYS_STATUS`] type's docs for details about these constants.
//!
//! Unless specified otherwise, all C strings in the API are NUL-terminated UTF-8-encoded strings.
//!
//! The only function exported by this library is [`aziot_keys_get_function_list`]. Call this function to get the version of the API
//! that this library exports, as well as the function pointers to the key operations. See its docs for more details.
//!
//! All calls to [`aziot_keys_get_function_list`] or any function in [`AZIOT_KEYS_FUNCTION_LIST`] are serialized, ie a function will not be called
//! while another function is running. However, it is not guaranteed that all function calls will be made from the same operating system thread.
//! Thus, implementations do not need to worry about locking to prevent concurrent access, but should also not store data in thread-local storage.

// DEVNOTE:
//
// Keep the above doc header in sync with cbindgen.prelude.h

// DEVNOTE:
//
// Transparent newtypes around integers must be specified as non-tuple structs.
// Eg `struct AZIOT_KEYS_STATUS { inner: c_uint }`, not `struct AZIOT_KEYS_STATUS(c_uint)`.
// This is because cbindgen requires constants to be assigned with struct expressions like `AZIOT_KEYS_STATUS { inner: 0 }`,
// whereas `AZIOT_KEYS_STATUS(0)` is a call expression that makes cbindgen ignore the constant.

// DEVNOTE:
//
// Some structs have a corresponding fn item like
//
//    #[cfg(any())]
//    #[no_mangle]
//    pub extern "C" fn cbindgen_unused_STRUCT() -> STRUCT { unimplemented!(); }
//
// These functions are required so that cbindgen emits the corresponding structs in the C header file. This is because cbindgen doesn't emit
// all pub structs that it finds, but only the ones that are referenced by pub fns. So for structs that are not referenced directly by any pub fns,
// we need these fake functions to reference them.
//
// Since cbindgen doesn't expand macros by default, we need to write these functions manually, as opposed to using a macro to generate them.
//
// The functions aren't actually part of the API of course, so the Makefile runs a post-processing step to strip these functions from the C header file
// and leave the structs. Specifically, it strips all functions whose names start with `cbindgen_unused_`, so ensure that all such functions follow
// this convention.
//
// The `#[cfg(any())]` on the functions is a cfg that always evaluates to false, so the functions don't actually get compiled into the final cdylib.
// cbindgen doesn't notice this.
//
// (Incidentally, this would backfire if we did use a macro to generate the fns and enabled expansion in the cbindgen config. This is because
// cbindgen does expansion via `rustc --pretty=expanded`, which also resolves `cfg()`s, so these fns would end up getting ignored by cbindgen too.

mod implementation;
mod key;
mod key_pair;

/// Error type. This is a transparent wrapper around a `std::os::raw::c_uint` (`unsigned int`).
///
/// Either `AZIOT_KEYS_SUCCESS` or one of the `AZIOT_KEYS_ERROR_*` constants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AZIOT_KEYS_STATUS {
    inner: std::os::raw::c_uint,
}

/// The operation succeeded.
pub const AZIOT_KEYS_SUCCESS: AZIOT_KEYS_STATUS = AZIOT_KEYS_STATUS { inner: 0 };

/// The library encountered an unrecoverable error. The process should exit as soon as possible.
pub const AZIOT_KEYS_ERROR_FATAL: AZIOT_KEYS_STATUS = AZIOT_KEYS_STATUS { inner: 1 };

/// The operation failed because a parameter has an invalid value.
pub const AZIOT_KEYS_ERROR_INVALID_PARAMETER: AZIOT_KEYS_STATUS = AZIOT_KEYS_STATUS { inner: 2 };

/// The library encountered an error with an external resource, such as an I/O error or RPC error.
pub const AZIOT_KEYS_ERROR_EXTERNAL: AZIOT_KEYS_STATUS = AZIOT_KEYS_STATUS { inner: 3 };

/// Represents the version of the API exported by this library.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AZIOT_KEYS_VERSION {
    inner: std::os::raw::c_uint,
}

/// Version 2.0.0.0
pub const AZIOT_KEYS_VERSION_2_0_0_0: AZIOT_KEYS_VERSION = AZIOT_KEYS_VERSION {
    inner: 0x02_00_00_00,
};

/// The base struct of all of function lists.
#[derive(Debug)]
#[repr(C)]
pub struct AZIOT_KEYS_FUNCTION_LIST {
    /// The version of the API represented in this function list.
    ///
    /// The specific subtype of `AZIOT_KEYS_FUNCTION_LIST` can be determined by inspecting this value.
    pub version: AZIOT_KEYS_VERSION,
}

/// The specific implementation of [`AZIOT_KEYS_FUNCTION_LIST`] for API version 2.0.0.0
#[derive(Debug)]
#[repr(C)]
pub struct AZIOT_KEYS_FUNCTION_LIST_2_0_0_0 {
    /// The value of `base.version` must be [`AZIOT_KEYS_VERSION_2_0_0_0`].
    pub base: AZIOT_KEYS_FUNCTION_LIST,

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
    /// - `AZIOT_KEYS_ERROR_INVALID_PARAMETER`:
    ///   - `name` is `NULL`.
    ///   - `name` is not recognized by this implementation.
    ///   - `value` is invalid.
    ///
    /// - `AZIOT_KEYS_ERROR_FATAL`
    pub set_parameter: unsafe extern "C" fn(
        name: *const std::os::raw::c_char,
        value: *const std::os::raw::c_char,
    ) -> AZIOT_KEYS_STATUS,

    /// Create or load a key identified by the specified `id`.
    ///
    /// - If a key with that ID exists, the key will be loaded from that URI and returned.
    /// - If a key with that ID does not exist, a new key will be created. It will be saved such that it can be looked up later using that same ID.
    ///
    /// `preferred_algorithms` dictates the caller's preference for the key algorithm. It is a string with components separated by COLON U+003A `:`,
    /// where each component specifies the name of an algorithm and will be attempted by the implementation in that order.
    /// The valid components are `"ec-p256"` for secp256r1, `"rsa-2048"` for 2048-bit RSA, `"rsa-4096"` for 4096-bit RSA, and `"*"` which indicates
    /// any algorithm of the implementation's choice. For example, the caller might use `"ec-p256:rsa-2048:*"` to indicate that it would like
    /// the implementation to use secp256r1, else RSA-2048 if that fails, else any other algorithm of the implementation's choice if that also fails.
    ///
    /// If an implementation does not recognize a particular component as an algorithm, or is unable to use the algorithm to generate a key pair,
    /// it should ignore that component and try the next one. If no components are left, the implementation should return an error.
    /// It is allowed for the implementation to unable to generate a key pair even if the wildcard algorithm is specified.
    ///
    /// If `preferred_algorithms` is NULL, it should be interpreted the same as if it was `"*"`.
    ///
    /// The public key is written to `ppublic_key` and the private key to `pprivate_key`.
    /// For keys generated by openssl in memory, the private and public components of a key live in the same `EVP_PKEY` value.
    /// However keys loaded from engines do differentiate between the two, so separate `EVP_PKEY` values are required.
    /// Even if the implementation generates keys in memory using openssl, it must copy the public parameters out of the key into a new `EVP_PKEY`
    /// and set `ppublic_parameters` to that.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_ERROR_INVALID_PARAMETER`:
    ///   - `id` is NULL.
    ///   - `ppublic_key` is `NULL`.
    ///   - `pprivate_key` is `NULL`.
    ///
    /// - `AZIOT_KEYS_ERROR_EXTERNAL`
    pub create_key_pair_if_not_exists: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        preferred_algorithms: *const std::os::raw::c_char,
    ) -> AZIOT_KEYS_STATUS,

    pub load_key_pair: unsafe extern "C" fn(id: *const std::os::raw::c_char) -> AZIOT_KEYS_STATUS,

    /// Gets the value of a parameter of the key identified by the specified `id`.
    ///
    /// `type_` must be set to one of the `AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_*` constants.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_ERROR_INVALID_PARAMETER`:
    ///   - `id` is NULL.
    ///   - The key specified by `id` does not exist.
    ///   - `type_` is not a valid parameter type for the key specified by `id`.
    ///
    /// - `AZIOT_KEYS_ERROR_EXTERNAL`
    pub get_key_pair_parameter: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        type_: AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE, // Would be nice to be able to use r#type, but https://github.com/eqrion/cbindgen/issues/410
        value: *mut std::os::raw::c_uchar,
        value_len: *mut usize,
    ) -> AZIOT_KEYS_STATUS,

    pub create_key_if_not_exists:
        unsafe extern "C" fn(id: *const std::os::raw::c_char, length: usize) -> AZIOT_KEYS_STATUS,

    pub load_key: unsafe extern "C" fn(id: *const std::os::raw::c_char) -> AZIOT_KEYS_STATUS,

    pub import_key: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        bytes: *const u8,
        bytes_len: usize,
    ) -> AZIOT_KEYS_STATUS,

    pub derive_key: unsafe extern "C" fn(
        base_id: *const std::os::raw::c_char,
        derivation_data: *const u8,
        derivation_data_len: usize,
        derived_key: *mut std::os::raw::c_uchar,
        derived_key_len: *mut usize,
    ) -> AZIOT_KEYS_STATUS,

    pub sign: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        mechanism: AZIOT_KEYS_SIGN_MECHANISM,
        parameters: *const std::ffi::c_void,
        digest: *const std::os::raw::c_uchar,
        digest_len: usize,
        signature: *mut std::os::raw::c_uchar,
        signature_len: *mut usize,
    ) -> AZIOT_KEYS_STATUS,

    /// Verifies the signature of the given digest using the key identified by the specified `id`.
    ///
    /// `mechanism` must be set to one of the `AZIOT_KEYS_SIGN_MECHANISM_*` constants.
    ///
    /// If the function returns `AZIOT_KEYS_SUCCESS`, then `ok` is set to 0 if the signature is invalid and non-zero if the signature is valid.
    ///
    /// # Errors
    ///
    /// - `AZIOT_KEYS_ERROR_INVALID_PARAMETER`:
    ///   - `id` is NULL.
    ///   - The key specified by `id` does not exist.
    ///   - `mechanism` is not a valid parameter type for the key specified by `id`.
    ///
    /// - `AZIOT_KEYS_ERROR_EXTERNAL`
    pub verify: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        mechanism: AZIOT_KEYS_SIGN_MECHANISM,
        parameters: *const std::ffi::c_void,
        digest: *const std::os::raw::c_uchar,
        digest_len: usize,
        signature: *const std::os::raw::c_uchar,
        signature_len: usize,
        ok: *mut std::os::raw::c_int,
    ) -> AZIOT_KEYS_STATUS,

    pub encrypt: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        mechanism: AZIOT_KEYS_ENCRYPT_MECHANISM,
        parameters: *const std::ffi::c_void,
        plaintext: *const std::os::raw::c_uchar,
        plaintext_len: usize,
        ciphertext: *mut std::os::raw::c_uchar,
        ciphertext_len: *mut usize,
    ) -> AZIOT_KEYS_STATUS,

    pub decrypt: unsafe extern "C" fn(
        id: *const std::os::raw::c_char,
        mechanism: AZIOT_KEYS_ENCRYPT_MECHANISM,
        parameters: *const std::ffi::c_void,
        ciphertext: *const std::os::raw::c_uchar,
        ciphertext_len: usize,
        plaintext: *mut std::os::raw::c_uchar,
        plaintext_len: *mut usize,
    ) -> AZIOT_KEYS_STATUS,
}

#[cfg(any())]
#[no_mangle]
pub extern "C" fn cbindgen_unused_AZIOT_KEYS_FUNCTION_LIST_2_0_0_0(
) -> AZIOT_KEYS_FUNCTION_LIST_2_0_0_0 {
    unimplemented!();
}

/// Get the list of functions for operations corresponding to the specified version.
///
/// Implementations can use this function for initialization, since it is guaranteed to be called before any operations.
/// However it is not an error to call this function multiple times, for the same or different version,
/// so implementations must ensure they only run their initialization once.
///
/// The pointer returned from this function must not be freed by the caller, and its contents must not be mutated.
///
/// # Errors
///
/// - `AZIOT_KEYS_ERROR_INVALID_PARAMETER`:
///   - `version` is not recognized by this implementation.
///   - `pfunction_list` is NULL.
#[no_mangle]
pub unsafe extern "C" fn aziot_keys_get_function_list(
    version: AZIOT_KEYS_VERSION,
    pfunction_list: *mut *const AZIOT_KEYS_FUNCTION_LIST,
) -> AZIOT_KEYS_STATUS {
    implementation::get_function_list(version, pfunction_list)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE {
    inner: std::os::raw::c_uint,
}

/// Used as the parameter type with `get_key_pair_parameter` to get the key algorithm.
///
/// The value returned by `get_key_pair_parameter` will be one of the `AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM_*` constants.
pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_ALGORITHM: AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE { inner: 1 };

/// Used as the parameter type with `get_key_pair_parameter` to get the curve OID of an EC key.
///
/// The value returned by `get_key_pair_parameter` will be a byte buffer containing a DER-encoded OID.
pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_EC_CURVE_OID: AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE { inner: 2 };

/// Used as the parameter type with `get_key_pair_parameter` to get the point of an EC key.
///
/// The value returned by `get_key_pair_parameter` will be a byte buffer containing a DER-encoded octet string in RFC 5490 format.
pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_EC_POINT: AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE { inner: 3 };

/// Used as the parameter type with `get_key_pair_parameter` to get the modulus of an RSA key.
///
/// The value returned by `get_key_pair_parameter` will be a byte buffer holding a big-endian bignum.
pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_RSA_MODULUS: AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE { inner: 4 };

/// Used as the parameter type with `get_key_pair_parameter` to get the exponent of an RSA key.
///
/// The value returned by `get_key_pair_parameter` will be a byte buffer holding a big-endian bignum.
pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE_RSA_EXPONENT: AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_TYPE { inner: 5 };

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM {
    inner: std::os::raw::c_uint,
}

pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM_EC: AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM { inner: 1 };

pub const AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM_RSA: AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM =
    AZIOT_KEYS_KEY_PAIR_PARAMETER_ALGORITHM { inner: 2 };

/// Represents the mechanism used for a sign operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AZIOT_KEYS_SIGN_MECHANISM {
    inner: std::os::raw::c_uint,
}

/// ECDSA
pub const AZIOT_KEYS_SIGN_MECHANISM_ECDSA: AZIOT_KEYS_SIGN_MECHANISM =
    AZIOT_KEYS_SIGN_MECHANISM { inner: 1 };

/// HMAC-SHA256
pub const AZIOT_KEYS_SIGN_MECHANISM_HMAC_SHA256: AZIOT_KEYS_SIGN_MECHANISM =
    AZIOT_KEYS_SIGN_MECHANISM { inner: 2 };

/// Sign with a derived key. The `parameters` parameter must be set to a `AZIOT_KEYS_SIGN_DERIVED_PARAMETERS` value.
pub const AZIOT_KEYS_SIGN_MECHANISM_DERIVED: AZIOT_KEYS_SIGN_MECHANISM =
    AZIOT_KEYS_SIGN_MECHANISM { inner: 3 };

/// Holds parameters for a sign operation with the [`AZIOT_KEYS_SIGN_MECHANISM_DERIVED`] mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct AZIOT_KEYS_SIGN_DERIVED_PARAMETERS {
    pub derivation_data: *const std::os::raw::c_uchar,
    pub derivation_data_len: usize,
    pub mechanism: AZIOT_KEYS_SIGN_MECHANISM,
    pub parameters: *const std::ffi::c_void,
}

#[cfg(any())]
#[no_mangle]
pub extern "C" fn cbindgen_unused_AZIOT_KEYS_SIGN_DERIVED_PARAMETERS(
) -> AZIOT_KEYS_SIGN_DERIVED_PARAMETERS {
    unimplemented!();
}

/// Represents the mechanism used for an encrypt operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct AZIOT_KEYS_ENCRYPT_MECHANISM {
    inner: std::os::raw::c_uint,
}

/// AEAD mechanism, like AES-256-GCM.
pub const AZIOT_KEYS_ENCRYPT_MECHANISM_AEAD: AZIOT_KEYS_ENCRYPT_MECHANISM =
    AZIOT_KEYS_ENCRYPT_MECHANISM { inner: 1 };

/// RSA with PKCS1 padding.
pub const AZIOT_KEYS_ENCRYPT_MECHANISM_RSA_PKCS1: AZIOT_KEYS_ENCRYPT_MECHANISM =
    AZIOT_KEYS_ENCRYPT_MECHANISM { inner: 2 };

/// RSA with no padding. Padding will have been performed by the caller.
pub const AZIOT_KEYS_ENCRYPT_MECHANISM_RSA_NO_PADDING: AZIOT_KEYS_ENCRYPT_MECHANISM =
    AZIOT_KEYS_ENCRYPT_MECHANISM { inner: 3 };

/// Encrypt with a derived key. The `parameters` parameter must be set to a `AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS` value.
pub const AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED: AZIOT_KEYS_ENCRYPT_MECHANISM =
    AZIOT_KEYS_ENCRYPT_MECHANISM { inner: 4 };

/// Holds parameters for an encrypt operation with the [`AZIOT_KEYS_ENCRYPT_MECHANISM_AEAD`] mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS {
    pub iv: *const std::os::raw::c_uchar,
    pub iv_len: usize,
    pub aad: *const std::os::raw::c_uchar,
    pub aad_len: usize,
}

#[cfg(any())]
#[no_mangle]
pub extern "C" fn cbindgen_unused_AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS(
) -> AZIOT_KEYS_ENCRYPT_AEAD_PARAMETERS {
    unimplemented!();
}

/// Holds parameters for an encrypt operation with the [`AZIOT_KEYS_ENCRYPT_MECHANISM_DERIVED`] mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS {
    pub derivation_data: *const std::os::raw::c_uchar,
    pub derivation_data_len: usize,
    pub mechanism: AZIOT_KEYS_ENCRYPT_MECHANISM,
    pub parameters: *const std::ffi::c_void,
}

#[cfg(any())]
#[no_mangle]
pub extern "C" fn cbindgen_unused_AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS(
) -> AZIOT_KEYS_ENCRYPT_DERIVED_PARAMETERS {
    unimplemented!();
}

/// Catches the error, if any, and returns it. Otherwise returns [`AZIOT_KEYS_SUCCESS`].
fn r#catch(f: impl FnOnce() -> Result<(), AZIOT_KEYS_STATUS>) -> AZIOT_KEYS_STATUS {
    match f() {
        Ok(()) => AZIOT_KEYS_SUCCESS,
        Err(err) => err,
    }
}
